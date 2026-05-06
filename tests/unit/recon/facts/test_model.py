"""Tests for maturity fact model objects."""
from __future__ import annotations

import json

import pytest

from d810.recon.facts import (
    FactMapping,
    FactObservation,
    FactStatus,
    ValidatedFactView,
    canonical_json,
)


def test_observation_serializes_deterministically() -> None:
    obs = FactObservation(
        fact_id="induction:blk10",
        kind="InductionCarrierFact",
        semantic_key="loop:byte_emit:counter",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.75,
        source_block=10,
        source_ea=0x180012345,
        payload={"b": 2, "a": [3, 1]},
        evidence=("blk[10] writes counter",),
    )

    assert obs.payload_json == '{"a":[3,1],"b":2}'
    assert json.loads(obs.evidence_json) == ["blk[10] writes counter"]

    round_trip = FactObservation.from_json_dict(obs.to_json_dict())
    assert round_trip == obs


def test_mapping_accepts_string_status_and_serializes() -> None:
    mapping = FactMapping(
        source_fact_id="return:carrier",
        source_maturity="MMAT_PREOPTIMIZED",
        target_maturity="MMAT_GLBOPT1",
        status="IDENTITY_LOST",  # type: ignore[arg-type]
        confidence=0.9,
        target_block=50,
        reason="carrier folded to arg+offset",
        payload={"writer": 50},
    )

    assert mapping.status is FactStatus.IDENTITY_LOST
    assert mapping.payload_json == '{"writer":50}'
    assert FactMapping.from_json_dict(mapping.to_json_dict()) == mapping


def test_confidence_is_validated() -> None:
    with pytest.raises(ValueError, match="confidence"):
        FactObservation(
            fact_id="bad",
            kind="ReturnCarrierFact",
            semantic_key="return",
            maturity="MMAT_GLBOPT1",
            phase="post_d810",
            confidence=1.5,
        )


def test_required_text_fields_are_validated() -> None:
    with pytest.raises(ValueError, match="fact_id"):
        FactObservation(
            fact_id="",
            kind="ReturnCarrierFact",
            semantic_key="return",
            maturity="MMAT_GLBOPT1",
            phase="post_d810",
            confidence=1.0,
        )


def test_validated_view_filters_inactive_observations() -> None:
    active = FactObservation(
        fact_id="call:130",
        kind="CallAnchorFact",
        semantic_key="call:0x11:0x4a",
        maturity="MMAT_CALLS",
        phase="pre_d810",
        confidence=1.0,
    )
    lost = FactObservation(
        fact_id="return:carrier",
        kind="ReturnCarrierFact",
        semantic_key="return:default",
        maturity="MMAT_CALLS",
        phase="pre_d810",
        confidence=0.8,
    )
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(active, lost),
        mappings=(
            FactMapping(
                source_fact_id="return:carrier",
                source_maturity="MMAT_CALLS",
                target_maturity="MMAT_GLBOPT1",
                status=FactStatus.IDENTITY_LOST,
                confidence=1.0,
            ),
        ),
    )

    assert view.active_observations == (active,)


def test_canonical_json_is_stable() -> None:
    assert canonical_json({"z": 1, "a": {"b": 2}}) == '{"a":{"b":2},"z":1}'
