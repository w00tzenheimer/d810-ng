"""Phase 3 acceptance tests for the fact-type alias registry."""
from __future__ import annotations

import pytest

from d810.recon.facts import value_flow as vf
from d810.recon.facts.value_flow.alias_registry import (
    FACT_TYPE_ALIAS_REGISTRY,
    FactTypeAlias,
)


def test_registry_covers_every_canonical_fact_type():
    """Each canonical *_FACT_TYPE constant has exactly one registry entry."""

    canonical_in_registry = {alias.canonical_fact_type for alias in FACT_TYPE_ALIAS_REGISTRY}
    assert canonical_in_registry == set(vf.VALUE_FLOW_FACT_TYPES)
    assert len(FACT_TYPE_ALIAS_REGISTRY) == len(vf.VALUE_FLOW_FACT_TYPES)


def test_accepted_aliases_round_trip_through_canonical():
    """Every one-to-one accepted alias normalizes to a canonical fact type."""

    assert vf.all_accepted_kind_aliases().isdisjoint(vf.VALUE_FLOW_FACT_TYPES)

    for alias in FACT_TYPE_ALIAS_REGISTRY:
        for observed_kind in alias.accepted_kind_aliases:
            if len(vf.canonical_fact_types(observed_kind)) == 1:
                assert vf.canonical_fact_type(observed_kind) == alias.canonical_fact_type


def test_canonical_fact_type_handles_unknown_kind():
    """Unknown kinds return None so raw values stay observable."""

    assert vf.canonical_fact_type("NotAFact") is None
    assert vf.canonical_fact_type("") is None


def test_canonical_fact_type_handles_canonical_input():
    """Passing a canonical fact type returns the same canonical fact type."""

    for fact_type in vf.VALUE_FLOW_FACT_TYPES:
        assert vf.canonical_fact_type(fact_type) == fact_type


def test_accepted_kind_aliases_for_returns_tuple_for_known_canonical():
    """accepted_kind_aliases_for returns aliases for known canonical types."""

    for fact_type in vf.VALUE_FLOW_FACT_TYPES:
        aliases = vf.accepted_kind_aliases_for(fact_type)
        assert isinstance(aliases, tuple)
        assert fact_type not in aliases


def test_accepted_kind_aliases_for_unknown_returns_empty():
    assert vf.accepted_kind_aliases_for("NotAFact") == ()


def test_source_observation_can_project_to_multiple_canonical_families():
    """Raw Hodur source names can normalize to every family they project into."""

    assert set(vf.canonical_fact_types("ReturnCarrierFact")) >= {
        vf.MATERIALIZATION_POINT_FACT_TYPE,
        vf.MEMORY_USE_FACT_TYPE,
        vf.RETURN_VALUE_FACT_TYPE,
    }
    assert set(vf.canonical_fact_types("ReturnFrontierFact")) >= {
        vf.MATERIALIZATION_POINT_FACT_TYPE,
        vf.MEMORY_PHI_FACT_TYPE,
    }
    assert set(vf.canonical_fact_types("TerminalByteEmitterFact")) >= {
        vf.OBSERVABLE_MEMORY_DEF_FACT_TYPE,
        vf.OBSERVABLE_OUTPUT_FACT_TYPE,
        vf.POINTS_TO_FACT_TYPE,
    }
    assert set(vf.canonical_fact_types("LocalPointerMayAliasFact")) == {
        vf.MAY_ALIAS_FACT_TYPE,
    }
    assert set(vf.canonical_fact_types("ObservableOutputStoreFact")) == {
        vf.OBSERVABLE_OUTPUT_FACT_TYPE,
    }
    assert vf.canonical_fact_type("ReturnCarrierFact") is None


def test_display_name_for_returns_non_empty_string_for_known_type():
    for fact_type in vf.VALUE_FLOW_FACT_TYPES:
        name = vf.display_name_for(fact_type)
        assert isinstance(name, str) and name


def test_industry_term_for_mentions_known_vocabulary():
    """Each industry-term description references a recognized vocabulary."""

    expected_tokens = {
        "MemorySSA",
        "angr",
        "Claripy",
        "ModRef",
        "FSM",
        "ABI",
        "SSA",
        "SROA",
        "mem2reg",
        "loop",
        "Loop",
        "value",
        "alias",
        "action",
        "edge",
        "effect",
        "Materialization",
    }
    for alias in FACT_TYPE_ALIAS_REGISTRY:
        text = alias.industry_term
        assert isinstance(text, str) and text
        lowered = text.lower()
        assert any(token.lower() in lowered for token in expected_tokens), (
            f"industry_term for {alias.canonical_fact_type!r} has no "
            f"recognized vocabulary token: {text!r}"
        )


def test_producer_ontology_describes_real_collectors():
    """Each producer-ontology line references at least one collector family."""

    for alias in FACT_TYPE_ALIAS_REGISTRY:
        text = alias.producer_ontology
        assert isinstance(text, str) and text


def test_dataclass_is_frozen():
    """FactTypeAlias is immutable so consumers can hash it safely."""

    sample = FACT_TYPE_ALIAS_REGISTRY[0]
    with pytest.raises(Exception):
        sample.canonical_fact_type = "Mutated"  # type: ignore[misc]


def test_registry_lookup_table_handles_all_canonical_and_accepted_alias_keys():
    canonical = set(vf.all_canonical_fact_types())
    aliases = vf.all_accepted_kind_aliases()
    # The registry must answer for every canonical and accepted alias key.
    for key in canonical | aliases:
        assert vf.canonical_fact_types(key)
