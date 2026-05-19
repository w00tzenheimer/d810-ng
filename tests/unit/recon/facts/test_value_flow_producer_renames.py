"""Phase 4 acceptance tests for producer-class renames.

Each test verifies that the canonical class name resolves to the same
collector implementation as the carrier-era class name. Producer facts use
their source-ontology strings; projected value-flow families use canonical
serialized type strings.
"""
from __future__ import annotations

from d810.recon.facts import collectors
from d810.recon.facts.value_flow import RETURN_VALUE_FACT_TYPE


def test_induction_variable_collector_alias_matches_legacy():
    from d810.recon.facts.collectors.induction_carrier import (
        InductionCarrierFactCollector,
        InductionVariableFactCollector,
    )

    assert InductionCarrierFactCollector is InductionVariableFactCollector
    # Confirm both spellings are re-exported by the collectors package.
    assert collectors.InductionVariableFactCollector is InductionVariableFactCollector
    assert collectors.InductionCarrierFactCollector is InductionVariableFactCollector
    assert InductionVariableFactCollector.fact_kinds == frozenset({"InductionCarrierFact"})


def test_loop_predicate_value_collector_alias_matches_legacy():
    from d810.recon.facts.collectors.loop_carrier import (
        LoopCarrierFactCollector,
        LoopPredicateValueFactCollector,
    )

    assert LoopCarrierFactCollector is LoopPredicateValueFactCollector
    assert collectors.LoopPredicateValueFactCollector is LoopPredicateValueFactCollector
    assert collectors.LoopCarrierFactCollector is LoopPredicateValueFactCollector
    assert LoopPredicateValueFactCollector.fact_kinds == frozenset({"LoopCarrierFact"})


def test_return_slot_collector_alias_matches_legacy():
    from d810.recon.facts.collectors.return_carrier import (
        ReturnCarrierFactCollector,
        ReturnSlotFactCollector,
        ReturnValueFactCollector,
    )

    assert ReturnCarrierFactCollector is ReturnSlotFactCollector
    assert collectors.ReturnSlotFactCollector is ReturnSlotFactCollector
    assert collectors.ReturnCarrierFactCollector is ReturnSlotFactCollector
    assert ReturnSlotFactCollector.fact_kinds == frozenset({"ReturnCarrierFact"})

    # ReturnValueFactCollector is a normalized projection producer over the
    # same Hodur return-slot evidence, not a theoretical placeholder.
    assert ReturnValueFactCollector.fact_kinds == frozenset({RETURN_VALUE_FACT_TYPE})


def test_ollvm_value_flow_evidence_collector_alias_matches_legacy():
    from d810.recon.facts.collectors.ollvm_semantic_carrier import (
        OllvmSemanticCarrierFactCollector,
        OllvmValueFlowEvidenceCollector,
    )

    assert OllvmSemanticCarrierFactCollector is OllvmValueFlowEvidenceCollector
    assert collectors.OllvmValueFlowEvidenceCollector is OllvmValueFlowEvidenceCollector
    assert collectors.OllvmSemanticCarrierFactCollector is OllvmValueFlowEvidenceCollector
    assert (
        OllvmValueFlowEvidenceCollector.fact_kinds
        == frozenset({"OllvmValueFlowEvidence"})
    )


def test_collector_module_all_exposes_canonical_and_legacy_names():
    """`from module import *` must see both spellings.

    The per-collector __all__ lists were initially defined with the
    legacy carrier-era name only. Star imports and API tooling that
    walks __all__ would then silently miss the canonical Phase 4
    classes. This test pins both spellings in __all__ for every
    renamed module.
    """

    from d810.recon.facts.collectors import (
        loop_carrier,
        ollvm_semantic_carrier,
        return_carrier,
    )

    assert set(loop_carrier.__all__) >= {
        "LoopCarrierFactCollector",
        "LoopPredicateValueFactCollector",
    }
    assert set(ollvm_semantic_carrier.__all__) >= {
        "OllvmSemanticCarrierFactCollector",
        "OllvmValueFlowEvidenceCollector",
    }
    assert set(return_carrier.__all__) >= {
        "ReturnCarrierFactCollector",
        "ReturnSlotFactCollector",
        "ReturnValueFactCollector",
    }
