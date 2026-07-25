"""Receipt-gated transport of immutable PREOPT native-body facts."""

from __future__ import annotations

from dataclasses import replace

import pytest

from d810.manager.frontend_normalization import (
    FrontendNormalizationPublicationError,
    SessionFrontendNormalizationPlanAuthority,
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


def test_prepared_body_facts_remain_invisible_until_exact_plan_receipt() -> None:
    plan, native_body, evidence, authority, fact, plan_authority = _case()

    plan_authority.record_prepared_body_fact(
        plan,
        native_body,
        fact,
        evidence_generation=evidence.generation,
    )

    assert (
        plan_authority.prepared_body_facts_for(
            0x40A560,
            evidence.generation,
            plan.plan_id,
        )
        is None
    )

    plan_authority.record_receipted_plan(plan, authority=authority)

    retained = plan_authority.prepared_body_facts_for(
        0x40A560,
        evidence.generation,
        plan.plan_id,
    )
    assert isinstance(retained, PreparedNativeBodyFactSnapshot)
    assert retained.plan_id == plan.plan_id
    assert retained.evidence_generation == evidence.generation
    assert retained.snapshot_id == (
        f"prepared-native-body:{plan.plan_id}:g{evidence.generation}:"
        f"r{authority.publication_revision}"
    )
    assert retained.bodies == (fact,)


def test_prepared_body_authority_rejects_fact_lineage_drift() -> None:
    plan, native_body, evidence, _authority, fact, plan_authority = _case()

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
