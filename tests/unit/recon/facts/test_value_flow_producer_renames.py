"""Phase 4 acceptance tests for producer-class renames.

Each test verifies that the canonical class name resolves to the same
collector implementation as the legacy carrier-era class name, and that
the emitted ``FactObservation.kind`` value continues to match the legacy
serialized string (so old diag SQLite snapshots remain queryable through
the Phase 3 alias registry).
"""
from __future__ import annotations

from d810.recon.facts import collectors


def test_induction_variable_collector_alias_matches_legacy():
    from d810.recon.facts.collectors.induction_carrier import (
        InductionCarrierFactCollector,
        InductionVariableFactCollector,
    )

    assert InductionCarrierFactCollector is InductionVariableFactCollector
    # Confirm both spellings are re-exported by the collectors package.
    assert collectors.InductionVariableFactCollector is InductionVariableFactCollector
    assert collectors.InductionCarrierFactCollector is InductionVariableFactCollector
    # The serialized FactObservation.kind value stays at the legacy string
    # so existing diag SQLite snapshots remain queryable. The Phase 3
    # alias registry handles canonical translation at the diagnostics
    # boundary.
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

    # ReturnValueFactCollector is a placeholder that records no producer
    # yet. It exists so consumers can target the canonical split shape now
    # without a second migration when a real producer is added.
    placeholder = ReturnValueFactCollector()
    assert placeholder.collect(None, func_ea=0, maturity=0, phase="pre_d810") == ()
    # fact_kinds stays empty until a real producer lands and the canonical
    # ReturnValueFact type is registered in the alias registry. An
    # unregistered fact-kind string would confuse the diagnostic
    # canonicalization layer.
    assert ReturnValueFactCollector.fact_kinds == frozenset()


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
        == frozenset({"OllvmSemanticCarrierFact"})
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
