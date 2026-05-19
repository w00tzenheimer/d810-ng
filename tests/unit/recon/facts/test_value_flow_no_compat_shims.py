"""Acceptance tests that carrier-era compatibility shims are gone."""
from __future__ import annotations

import importlib.util

from d810.recon.facts import collectors
from d810.recon.facts import value_flow as vf
from d810.recon.facts.model import FactObservation


def test_carrier_import_shim_is_removed() -> None:
    assert importlib.util.find_spec("d810.recon.facts.carrier") is None


def test_value_flow_fact_types_are_canonical_and_complete() -> None:
    assert isinstance(vf.VALUE_FLOW_FACT_TYPES, frozenset)
    assert len(vf.VALUE_FLOW_FACT_TYPES) == 19
    assert vf.MAY_ALIAS_FACT_TYPE in vf.VALUE_FLOW_FACT_TYPES
    assert vf.OBSERVABLE_OUTPUT_FACT_TYPE in vf.VALUE_FLOW_FACT_TYPES
    assert "SameCarrierAliasFact" not in vf.VALUE_FLOW_FACT_TYPES
    assert "ObservableStoreFact" not in vf.VALUE_FLOW_FACT_TYPES


def test_old_collector_class_aliases_are_not_exported() -> None:
    assert not hasattr(collectors, "InductionCarrierFactCollector")
    assert not hasattr(collectors, "LoopCarrierFactCollector")
    assert not hasattr(collectors, "ReturnCarrierFactCollector")
    assert not hasattr(collectors, "OllvmSemanticCarrierFactCollector")


def _induction_observation() -> FactObservation:
    return FactObservation(
        fact_id="induction:test:1",
        kind="InductionCarrierFact",
        semantic_key="induction:test",
        maturity="MMAT_GLBOPT1",
        phase="pre_d810",
        confidence=1.0,
        source_block=0,
        source_ea=0x180010000,
        block_fingerprint="blk[0].0:op_1",
        mop_signature="InductionCarrierFact:signature",
        payload={
            "dest_stkoff": 0x20,
            "dest_token": "%var_20",
            "carrier_kind": "stack",
            "step": 1,
        },
        evidence=("synthetic evidence",),
    )


def test_projection_is_idempotent_for_canonical_value_flow_facts() -> None:
    obs = _induction_observation()
    first = vf.project_value_flow_facts((obs,))
    second = vf.project_value_flow_facts(first)

    assert first == second


def test_per_family_submodule_imports_resolve_to_canonical_values() -> None:
    from d810.recon.facts.value_flow.may_alias import MAY_ALIAS_FACT_TYPE
    from d810.recon.facts.value_flow.observable_output import (
        OBSERVABLE_OUTPUT_FACT_TYPE,
    )

    assert MAY_ALIAS_FACT_TYPE == "MayAliasFact"
    assert OBSERVABLE_OUTPUT_FACT_TYPE == "ObservableOutputFact"
