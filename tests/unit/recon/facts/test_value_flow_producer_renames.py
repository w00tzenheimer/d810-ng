"""Acceptance tests for producer-class renames."""
from __future__ import annotations

from d810.analyses.value_flow import collectors
from d810.analyses.value_flow import RETURN_VALUE_FACT_TYPE


def test_induction_variable_collector_is_canonical_export() -> None:
    from d810.analyses.value_flow.induction_carrier import (
        InductionVariableFactCollector,
    )

    assert collectors.InductionVariableFactCollector is InductionVariableFactCollector
    assert not hasattr(collectors, "InductionCarrierFactCollector")
    assert InductionVariableFactCollector.fact_kinds == frozenset({"InductionCarrierFact"})


def test_loop_predicate_value_collector_is_canonical_export() -> None:
    from d810.analyses.value_flow.loop_carrier import (
        LoopPredicateValueFactCollector,
    )

    assert collectors.LoopPredicateValueFactCollector is LoopPredicateValueFactCollector
    assert not hasattr(collectors, "LoopCarrierFactCollector")
    assert LoopPredicateValueFactCollector.fact_kinds == frozenset({"LoopCarrierFact"})


def test_return_slot_and_return_value_collectors_are_canonical_exports() -> None:
    from d810.analyses.value_flow.return_carrier import (
        ReturnSlotFactCollector,
        ReturnValueFactCollector,
    )

    assert collectors.ReturnSlotFactCollector is ReturnSlotFactCollector
    assert not hasattr(collectors, "ReturnCarrierFactCollector")
    assert ReturnSlotFactCollector.fact_kinds == frozenset({"ReturnCarrierFact"})

    # ReturnValueFactCollector is a normalized projection producer over the
    # same Hodur return-slot evidence, not a theoretical placeholder.
    assert ReturnValueFactCollector.fact_kinds == frozenset({RETURN_VALUE_FACT_TYPE})


def test_ollvm_value_flow_evidence_collector_is_profile_local() -> None:
    from d810.families.state_machine_cff.ollvm_carrier_profile import (
        OllvmCarrierRawEvidenceCollector,
    )

    assert not hasattr(collectors, "OllvmValueFlowEvidenceCollector")
    assert not hasattr(collectors, "OllvmCarrierRawEvidenceCollector")
    assert not hasattr(collectors, "OllvmSemanticCarrierFactCollector")
    assert (
        OllvmCarrierRawEvidenceCollector.fact_kinds
        == frozenset({"OllvmValueFlowEvidence"})
    )


def test_collector_module_all_exposes_only_canonical_names() -> None:
    from d810.analyses.value_flow import loop_carrier, return_carrier
    from d810.families.state_machine_cff import ollvm_carrier_profile

    assert loop_carrier.__all__ == ["LoopPredicateValueFactCollector"]
    assert ollvm_carrier_profile.__all__ == [
        "OLLVM_CARRIER_PROFILE_MODULE",
        "OLLVM_CARRIER_PROFILE_NAME",
        "OllvmCarrierBranchOwnershipOracle",
        "OllvmCarrierProfileFactCollector",
        "OllvmCarrierRawEvidenceCollector",
        "collect_ollvm_branch_ownership_refiners",
        "collect_ollvm_post_execute_carrier_facts",
        "collect_ollvm_profile_fact_observations",
        "collect_ollvm_raw_semantic_carrier_facts",
        "project_ollvm_value_flow_evidence",
    ]
    assert return_carrier.__all__ == [
        "ReturnSlotFactCollector",
        "ReturnValueFactCollector",
    ]
