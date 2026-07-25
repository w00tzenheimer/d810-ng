"""Receipt-gated transport of immutable PREOPT native-body facts."""

from __future__ import annotations

from dataclasses import replace

import pytest

from d810.manager.frontend_normalization import (
    FrontendNormalizationPublicationError,
    SessionFrontendNormalizationPlanAuthority,
)
from d810.transforms.fragment_plan import FragmentBlockRole
from d810.transforms.frontend_normalization import (
    FrontendNormalizationGenerationPlan,
)
from d810.transforms.prepared_native_body import PreparedNativeBodyFactSnapshot
from tests.unit.transforms.test_canonical_semantic_fragment import (
    _detached_reference_direct_route_case,
)
from tests.unit.transforms.test_detached_direct_route_projection import (
    _prepared_body_fact,
)


def _case():
    plan, evidence, authority, _reference_route = (
        _detached_reference_direct_route_case()
    )
    (native_body,) = plan.native_bodies
    plan_authority = SessionFrontendNormalizationPlanAuthority(
        function_ea=0x40A560,
        native_key=plan.native_key,
    )
    return (
        plan,
        native_body,
        evidence,
        authority,
        _prepared_body_fact(plan),
        plan_authority,
    )


def _scoped_generation_case():
    complete_plan, native_body, evidence, authority, _fact, plan_authority = _case()
    suffix = "root@0x40BB51"
    work_item_plan_id = f"{complete_plan.plan_id}:{suffix}"
    work_item_body_id = f"{native_body.body_id}:{suffix}"
    scope = complete_plan.work_item_scope
    assert scope is not None
    work_item_plan = replace(
        complete_plan,
        plan_id=work_item_plan_id,
        atomic_group_id=f"{complete_plan.atomic_group_id}:{suffix}",
        blocks=tuple(
            replace(block, native_body_id=work_item_body_id)
            if block.role is FragmentBlockRole.IMPORTED
            else block
            for block in complete_plan.blocks
        ),
        work_item_scope=replace(scope, work_item_id=work_item_plan_id),
        native_bodies=(replace(native_body, body_id=work_item_body_id),),
    )
    generation_plan = FrontendNormalizationGenerationPlan(
        complete_plan=complete_plan,
        work_item_plan=work_item_plan,
    )
    work_item_authority = replace(
        authority,
        source_plan_id=complete_plan.plan_id,
        source_atomic_group_id=complete_plan.atomic_group_id,
        work_item_id=work_item_plan_id,
        published_operation_ids=tuple(
            operation.operation_id for operation in work_item_plan.operations
        ),
        selected_obligation_ids=scope.selected_obligation_ids,
        remaining_obligation_ids=scope.remaining_obligation_ids,
        unreachable_obligation_ids=scope.unreachable_obligation_ids,
    )
    return (
        generation_plan,
        evidence,
        work_item_authority,
        _prepared_body_fact(work_item_plan),
        plan_authority,
    )


def test_prepared_body_facts_remain_invisible_until_exact_plan_receipt() -> None:
    generation_plan, evidence, authority, fact, plan_authority = (
        _scoped_generation_case()
    )
    work_item_plan = generation_plan.work_item_plan
    (native_body,) = work_item_plan.native_bodies

    plan_authority.record_prepared_body_fact(
        work_item_plan,
        native_body,
        fact,
        evidence_generation=evidence.generation,
    )

    assert (
        plan_authority.prepared_work_item_for(
            0x40A560,
            evidence.generation,
            generation_plan.complete_plan.plan_id,
            "native@0x40BB51",
        )
        is None
    )

    plan_authority.record_receipted_generation(
        generation_plan,
        authority=authority,
    )

    retained = plan_authority.prepared_work_item_for(
        0x40A560,
        evidence.generation,
        generation_plan.complete_plan.plan_id,
        "native@0x40BB51",
    )
    assert retained is not None
    assert isinstance(retained.prepared_bodies, PreparedNativeBodyFactSnapshot)
    assert retained.prepared_bodies.plan_id == work_item_plan.plan_id
    assert retained.prepared_bodies.evidence_generation == evidence.generation
    assert retained.prepared_bodies.snapshot_id == (
        f"prepared-native-body:{work_item_plan.plan_id}:g{evidence.generation}:"
        f"r{authority.publication_revision}"
    )
    assert retained.prepared_bodies.bodies == (fact,)


def test_prepared_body_authority_rejects_fact_lineage_drift() -> None:
    generation_plan, evidence, _authority, fact, plan_authority = (
        _scoped_generation_case()
    )
    plan = generation_plan.work_item_plan
    (native_body,) = plan.native_bodies

    with pytest.raises(
        FrontendNormalizationPublicationError,
        match="changed plan lineage",
    ):
        plan_authority.record_prepared_body_fact(
            plan,
            native_body,
            replace(fact, plan_id="another-plan"),
            evidence_generation=evidence.generation,
        )


def test_scoped_prepared_body_is_exposed_through_its_complete_plan_lineage() -> None:
    generation_plan, evidence, authority, fact, plan_authority = (
        _scoped_generation_case()
    )
    work_item_plan = generation_plan.work_item_plan
    (work_item_body,) = work_item_plan.native_bodies

    plan_authority.record_prepared_body_fact(
        work_item_plan,
        work_item_body,
        fact,
        evidence_generation=evidence.generation,
    )
    plan_authority.record_receipted_generation(
        generation_plan,
        authority=authority,
    )

    retained = plan_authority.prepared_work_item_for(
        0x40A560,
        evidence.generation,
        generation_plan.complete_plan.plan_id,
        "native@0x40BB51",
    )

    assert retained is not None
    assert retained.source_plan_id == generation_plan.complete_plan.plan_id
    assert retained.work_item_plan == work_item_plan
    assert retained.authority == authority
    assert isinstance(retained.prepared_bodies, PreparedNativeBodyFactSnapshot)
    assert retained.prepared_bodies.plan_id == work_item_plan.plan_id
    assert retained.prepared_bodies.bodies == (fact,)
    assert plan_authority.plan_for(0x40A560, evidence.generation) == (
        generation_plan.complete_plan,
        authority,
    )


def test_scoped_prepared_body_does_not_authorize_an_unpublished_block() -> None:
    generation_plan, evidence, authority, fact, plan_authority = (
        _scoped_generation_case()
    )
    work_item_plan = generation_plan.work_item_plan
    (work_item_body,) = work_item_plan.native_bodies
    plan_authority.record_prepared_body_fact(
        work_item_plan,
        work_item_body,
        fact,
        evidence_generation=evidence.generation,
    )
    plan_authority.record_receipted_generation(
        generation_plan,
        authority=authority,
    )

    assert (
        plan_authority.prepared_work_item_for(
            0x40A560,
            evidence.generation,
            generation_plan.complete_plan.plan_id,
            "not-in-the-published-work-item",
        )
        is None
    )
