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


def test_legacy_kinds_round_trip_through_canonical():
    """Every legacy serialized kind normalizes to a canonical fact type."""

    assert vf.all_legacy_kinds().isdisjoint(vf.VALUE_FLOW_FACT_TYPES)

    for alias in FACT_TYPE_ALIAS_REGISTRY:
        for legacy in alias.legacy_kinds:
            assert vf.canonical_fact_type(legacy) == alias.canonical_fact_type


def test_canonical_fact_type_handles_unknown_kind():
    """Unknown kinds return None so raw values stay observable."""

    assert vf.canonical_fact_type("NotAFact") is None
    assert vf.canonical_fact_type("") is None


def test_canonical_fact_type_handles_canonical_input():
    """Passing a canonical fact type returns the same canonical fact type."""

    for fact_type in vf.VALUE_FLOW_FACT_TYPES:
        assert vf.canonical_fact_type(fact_type) == fact_type


def test_legacy_kinds_for_returns_tuple_for_known_canonical():
    """legacy_kinds_for returns the legacy tuple for known canonical types."""

    for fact_type in vf.VALUE_FLOW_FACT_TYPES:
        legacy = vf.legacy_kinds_for(fact_type)
        assert isinstance(legacy, tuple)
        assert len(legacy) >= 1
        assert fact_type not in legacy


def test_legacy_kinds_for_unknown_returns_empty():
    assert vf.legacy_kinds_for("NotAFact") == ()


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


def test_registry_lookup_table_handles_all_canonical_and_legacy_keys():
    canonical = set(vf.all_canonical_fact_types())
    legacy = vf.all_legacy_kinds()
    # The registry's lookup must answer for every canonical and legacy key.
    for key in canonical | legacy:
        assert vf.canonical_fact_type(key) is not None
