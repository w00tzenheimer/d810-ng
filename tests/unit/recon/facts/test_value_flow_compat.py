"""Acceptance tests for the value-flow terminology rename.

These tests verify that the canonical ``d810.recon.facts.value_flow``
package exposes the rename surface required by
``docs/plans/2026-05-18-value-flow-terminology-rename-design.md`` while
preserving the carrier-named import shim.
"""
from __future__ import annotations

import pytest

from d810.recon.facts import carrier as carrier_mod
from d810.recon.facts import value_flow as vf
from d810.recon.facts.model import FactObservation


CANONICAL_TO_LEGACY = {
    "OBSERVABLE_MEMORY_DEF_FACT_TYPE": "OBSERVABLE_STORE_FACT_KIND",
    "SCALAR_PROMOTION_FACT_TYPE": "CARRIER_STORE_PROMOTION_FACT_KIND",
    "MUST_ALIAS_FACT_TYPE": "SAME_CARRIER_ALIAS_FACT_KIND",
    "SCALAR_REPLACEMENT_FACT_TYPE": "LOCAL_STORAGE_SCALARIZATION_FACT_KIND",
    "SYMBOLIC_EXPRESSION_FACT_TYPE": "EXPRESSION_CARRIER_FACT_KIND",
    "LOOP_PREDICATE_VALUE_FACT_TYPE": "LOOP_PREDICATE_CARRIER_FACT_KIND",
    "CALL_RETURN_VALUE_FACT_TYPE": "CALL_RESULT_CARRIER_FACT_KIND",
    "INDUCTION_VARIABLE_FACT_TYPE": "INDUCTION_CARRIER_FACT_KIND",
    "MATERIALIZATION_POINT_FACT_TYPE": "TERMINAL_MATERIALIZATION_FACT_KIND",
    "STATE_WRITE_FACT_TYPE": "STATE_VARIABLE_WRITE_FACT_KIND",
    "STATE_TRANSITION_FACT_TYPE": "STATE_TRANSITION_CARRIER_FACT_KIND",
    "EFFECT_PATH_FACT_TYPE": "SIDE_EFFECT_CORRIDOR_FACT_KIND",
    "CALL_EFFECT_SUMMARY_FACT_TYPE": "CALL_SIDE_EFFECT_ANCHOR_FACT_KIND",
}


@pytest.mark.parametrize("canonical_name,legacy_name", sorted(CANONICAL_TO_LEGACY.items()))
def test_canonical_constant_matches_compat_import_value(canonical_name, legacy_name):
    """Carrier-era constant names now resolve to canonical serialized values."""

    assert getattr(vf, canonical_name) == getattr(carrier_mod, legacy_name)


def test_canonical_constants_exposed_from_both_modules():
    """Both spellings are importable from carrier and value_flow."""

    for canonical_name in CANONICAL_TO_LEGACY:
        assert getattr(vf, canonical_name) == getattr(carrier_mod, canonical_name)


def test_value_flow_fact_types_matches_generic_carrier_fact_kinds():
    """The canonical type-set is exposed from both package surfaces."""

    assert vf.VALUE_FLOW_FACT_TYPES == carrier_mod.GENERIC_CARRIER_FACT_KINDS
    assert isinstance(vf.VALUE_FLOW_FACT_TYPES, frozenset)
    assert len(vf.VALUE_FLOW_FACT_TYPES) == 13


def test_projection_function_alias_is_identity():
    """``project_value_flow_facts`` is an alias for ``project_carrier_fact_families``."""

    assert vf.project_value_flow_facts is carrier_mod.project_carrier_fact_families
    assert vf.is_value_flow_fact is carrier_mod.is_generic_carrier_fact
    assert vf.production_value_flow_fact is carrier_mod.production_carrier_fact
    assert vf.exact_source_identity is carrier_mod.exact_source_identity


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


def test_projection_idempotent_under_canonical_alias():
    """``project_value_flow_facts`` is idempotent."""

    obs = _induction_observation()
    first = vf.project_value_flow_facts((obs,))
    second = vf.project_value_flow_facts(first)
    assert first == second
    # Cross-spelling agreement
    third = carrier_mod.project_carrier_fact_families(first)
    assert first == third


def test_per_family_submodule_imports_resolve_to_canonical_value():
    """Each per-family submodule re-exports the canonical constant."""

    from d810.recon.facts.value_flow.observable_memory_def import (
        OBSERVABLE_MEMORY_DEF_FACT_TYPE,
    )
    from d810.recon.facts.value_flow.must_alias import MUST_ALIAS_FACT_TYPE
    from d810.recon.facts.value_flow.scalar_promotion import (
        SCALAR_PROMOTION_FACT_TYPE,
    )
    from d810.recon.facts.value_flow.scalar_replacement import (
        SCALAR_REPLACEMENT_FACT_TYPE,
    )
    from d810.recon.facts.value_flow.symbolic_expression import (
        SYMBOLIC_EXPRESSION_FACT_TYPE,
    )
    from d810.recon.facts.value_flow.loop_predicate_value import (
        LOOP_PREDICATE_VALUE_FACT_TYPE,
    )
    from d810.recon.facts.value_flow.call_return_value import (
        CALL_RETURN_VALUE_FACT_TYPE,
    )
    from d810.recon.facts.value_flow.induction_variable import (
        INDUCTION_VARIABLE_FACT_TYPE,
    )
    from d810.recon.facts.value_flow.materialization_point import (
        MATERIALIZATION_POINT_FACT_TYPE,
    )
    from d810.recon.facts.value_flow.state_write import STATE_WRITE_FACT_TYPE
    from d810.recon.facts.value_flow.state_transition import (
        STATE_TRANSITION_FACT_TYPE,
    )
    from d810.recon.facts.value_flow.effect_path import EFFECT_PATH_FACT_TYPE
    from d810.recon.facts.value_flow.call_effect_summary import (
        CALL_EFFECT_SUMMARY_FACT_TYPE,
    )

    assert OBSERVABLE_MEMORY_DEF_FACT_TYPE == "ObservableMemoryDefFact"
    assert MUST_ALIAS_FACT_TYPE == "MustAliasFact"
    assert SCALAR_PROMOTION_FACT_TYPE == "ScalarPromotionFact"
    assert SCALAR_REPLACEMENT_FACT_TYPE == "ScalarReplacementFact"
    assert SYMBOLIC_EXPRESSION_FACT_TYPE == "SymbolicExpressionFact"
    assert LOOP_PREDICATE_VALUE_FACT_TYPE == "LoopPredicateValueFact"
    assert CALL_RETURN_VALUE_FACT_TYPE == "CallReturnValueFact"
    assert INDUCTION_VARIABLE_FACT_TYPE == "InductionVariableFact"
    assert MATERIALIZATION_POINT_FACT_TYPE == "MaterializationPointFact"
    assert STATE_WRITE_FACT_TYPE == "StateWriteFact"
    assert STATE_TRANSITION_FACT_TYPE == "StateTransitionFact"
    assert EFFECT_PATH_FACT_TYPE == "EffectPathFact"
    assert CALL_EFFECT_SUMMARY_FACT_TYPE == "CallEffectSummaryFact"


def test_carrier_import_shim_remains_working():
    """The carrier module remains an import shim for migrated constants."""

    from d810.recon.facts.carrier import (
        CALL_RESULT_CARRIER_FACT_KIND,
        CALL_SIDE_EFFECT_ANCHOR_FACT_KIND,
        CARRIER_STORE_PROMOTION_FACT_KIND,
        EXPRESSION_CARRIER_FACT_KIND,
        GENERIC_CARRIER_FACT_KINDS,
        INDUCTION_CARRIER_FACT_KIND,
        LOCAL_STORAGE_SCALARIZATION_FACT_KIND,
        LOOP_PREDICATE_CARRIER_FACT_KIND,
        OBSERVABLE_STORE_FACT_KIND,
        SAME_CARRIER_ALIAS_FACT_KIND,
        SIDE_EFFECT_CORRIDOR_FACT_KIND,
        STATE_TRANSITION_CARRIER_FACT_KIND,
        STATE_VARIABLE_WRITE_FACT_KIND,
        TERMINAL_MATERIALIZATION_FACT_KIND,
        project_carrier_fact_families,
    )

    assert OBSERVABLE_STORE_FACT_KIND in GENERIC_CARRIER_FACT_KINDS
    assert callable(project_carrier_fact_families)
    # Spot check: a carrier-era constant name points at the canonical
    # serialized value.
    assert CALL_RESULT_CARRIER_FACT_KIND == vf.CALL_RETURN_VALUE_FACT_TYPE
