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


def test_return_carrier_sites_for_block_filters_by_block_serial() -> None:
    """``ValidatedFactView.return_carrier_sites_for_block`` returns
    only ``ReturnCarrierFact`` observations whose payload's
    ``upstream_writer_block_serial`` matches the requested serial,
    after stale / REMAPPED / CONTRADICTED / SUPERSEDED / IDENTITY_LOST
    filtering applied by ``active_observations``."""
    matching = FactObservation(
        fact_id="return:matching",
        kind="ReturnCarrierFact",
        semantic_key="return:matching:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        payload={"upstream_writer_block_serial": 93},
    )
    other_block = FactObservation(
        fact_id="return:other",
        kind="ReturnCarrierFact",
        semantic_key="return:other:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        payload={"upstream_writer_block_serial": 100},
    )
    other_kind = FactObservation(
        fact_id="byte_emit:matching_block",
        kind="TerminalByteEmitterFact",
        semantic_key="byte:matching:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        payload={"upstream_writer_block_serial": 93},
    )
    no_payload = FactObservation(
        fact_id="return:nopayload",
        kind="ReturnCarrierFact",
        semantic_key="return:nopayload:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
    )
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(matching, other_block, other_kind, no_payload),
    )

    sites = view.return_carrier_sites_for_block(93)

    # Only the ReturnCarrierFact with the matching block_serial returns.
    assert len(sites) == 1
    assert sites[0].fact_id == "return:matching"


def test_return_carrier_sites_for_block_excludes_stale_facts() -> None:
    """A ReturnCarrierFact whose lifecycle status is IDENTITY_LOST /
    STALE / etc. must NOT appear in the result -- the helper goes
    through ``active_observations``."""
    stale = FactObservation(
        fact_id="return:stale",
        kind="ReturnCarrierFact",
        semantic_key="return:stale:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        payload={"upstream_writer_block_serial": 93},
    )
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(stale,),
        mappings=(
            FactMapping(
                source_fact_id="return:stale",
                source_maturity="MMAT_LOCOPT",
                target_maturity="MMAT_GLBOPT1",
                status=FactStatus.IDENTITY_LOST,
                confidence=1.0,
            ),
        ),
    )

    assert view.return_carrier_sites_for_block(93) == ()


def test_return_carrier_sites_for_block_returns_empty_on_invalid_input() -> None:
    """Non-int / out-of-range block serials must return an empty tuple
    rather than raising."""
    obs = FactObservation(
        fact_id="return:matching",
        kind="ReturnCarrierFact",
        semantic_key="return:matching:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        payload={"upstream_writer_block_serial": 93},
    )
    view = ValidatedFactView(maturity="MMAT_GLBOPT1", observations=(obs,))

    assert view.return_carrier_sites_for_block("not-an-int") == ()  # type: ignore[arg-type]
    # Block serial 0 is not "matching" since the fact is for blk[93].
    assert view.return_carrier_sites_for_block(0) == ()


def test_stale_return_carrier_hazards_require_exact_ea_target_mapping() -> None:
    stale = FactObservation(
        fact_id="return:stale",
        kind="ReturnCarrierFact",
        semantic_key="return:stale:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        source_ea=0x401000,
        payload={
            "upstream_writer_block_serial": 93,
            "upstream_writer_ea": 0x401020,
            "upstream_writer_var_refs": ["228", "650"],
        },
    )
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(stale,),
        mappings=(
            FactMapping(
                source_fact_id="return:stale",
                source_maturity="MMAT_LOCOPT",
                target_maturity="MMAT_GLBOPT1",
                status=FactStatus.IDENTITY_LOST,
                confidence=1.0,
            ),
        ),
    )

    assert view.return_carrier_sites_for_block(93) == ()
    assert view.stale_return_carrier_hazards_for_block(93) == ()


def test_stale_return_carrier_hazards_match_lifecycle_target_block() -> None:
    stale = FactObservation(
        fact_id="return:stale",
        kind="ReturnCarrierFact",
        semantic_key="return:stale:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        source_ea=0x401000,
        payload={
            "upstream_writer_block_serial": 254,
            "upstream_writer_ea": 0x401020,
            "upstream_writer_var_refs": ["228", "650"],
        },
    )
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(stale,),
        mappings=(
            FactMapping(
                source_fact_id="return:stale",
                source_maturity="MMAT_LOCOPT",
                target_maturity="MMAT_GLBOPT1",
                status=FactStatus.IDENTITY_LOST,
                confidence=1.0,
                target_block=94,
                target_ea=0x401000,
            ),
        ),
    )

    assert view.stale_return_carrier_hazards_for_block(94) == (stale,)


def test_stale_return_carrier_hazards_ignore_contradicted_fact() -> None:
    stale = FactObservation(
        fact_id="return:contradicted",
        kind="ReturnCarrierFact",
        semantic_key="return:contradicted:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        source_ea=0x401000,
        payload={
            "upstream_writer_block_serial": 93,
            "upstream_writer_ea": 0x401020,
            "upstream_writer_var_refs": ["228"],
        },
    )
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(stale,),
        mappings=(
            FactMapping(
                source_fact_id="return:contradicted",
                source_maturity="MMAT_LOCOPT",
                target_maturity="MMAT_GLBOPT1",
                status=FactStatus.IDENTITY_LOST,
                confidence=1.0,
            ),
            FactMapping(
                source_fact_id="return:contradicted",
                source_maturity="MMAT_LOCOPT",
                target_maturity="MMAT_GLBOPT1",
                status=FactStatus.CONTRADICTED,
                confidence=1.0,
            ),
        ),
    )

    assert view.stale_return_carrier_hazards_for_block(93) == ()


def test_terminal_byte_emit_sites_for_block_filters_by_role_and_destination() -> None:
    """``ValidatedFactView.terminal_byte_emit_sites_for_block`` returns
    only ``TerminalByteEmitterFact`` rows with ``corridor_role ==
    "terminal_tail"`` whose ``destination_block`` (or fallback
    ``block_serial``) matches the requested serial.  Non-terminal and
    guard-only emitter facts are excluded so the bulk emitter
    ``STATE_2FBA4611`` corridor is not protected by mistake."""
    terminal_match = FactObservation(
        fact_id="byte_emit:terminal_match",
        kind="TerminalByteEmitterFact",
        semantic_key="byte:terminal_match:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        source_ea=0x180015906,
        payload={
            "corridor_role": "terminal_tail",
            "byte_index": 1,
            "destination_block": 143,
            "block_serial": 211,
        },
    )
    non_terminal = FactObservation(
        fact_id="byte_emit:non_terminal",
        kind="TerminalByteEmitterFact",
        semantic_key="byte:non_terminal:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        payload={
            "corridor_role": "non_terminal_byte_emitter",
            "byte_index": 2,
            "destination_block": 143,
            "block_serial": 143,
        },
    )
    guard_only = FactObservation(
        fact_id="byte_emit:guard_only",
        kind="TerminalByteEmitterFact",
        semantic_key="byte:guard_only:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        payload={
            "corridor_role": "guard_only",
            "byte_index": 0,
            "destination_block": 143,
            "block_serial": 143,
        },
    )
    other_block = FactObservation(
        fact_id="byte_emit:other_block",
        kind="TerminalByteEmitterFact",
        semantic_key="byte:other_block:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        payload={
            "corridor_role": "terminal_tail",
            "byte_index": 5,
            "destination_block": 200,
            "block_serial": 200,
        },
    )
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(terminal_match, non_terminal, guard_only, other_block),
    )

    sites = view.terminal_byte_emit_sites_for_block(143)

    assert len(sites) == 1
    assert sites[0].fact_id == "byte_emit:terminal_match"

    # Invalid input must yield an empty tuple.
    assert view.terminal_byte_emit_sites_for_block("not-an-int") == ()  # type: ignore[arg-type]


def test_terminal_byte_emit_sites_for_block_excludes_stale_facts() -> None:
    """Lifecycle-invalidated rows must be filtered out via
    ``active_observations``."""
    stale = FactObservation(
        fact_id="byte_emit:stale",
        kind="TerminalByteEmitterFact",
        semantic_key="byte:stale:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        payload={
            "corridor_role": "terminal_tail",
            "byte_index": 1,
            "destination_block": 143,
            "block_serial": 143,
        },
    )
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(stale,),
        mappings=(
            FactMapping(
                source_fact_id="byte_emit:stale",
                source_maturity="MMAT_LOCOPT",
                target_maturity="MMAT_GLBOPT1",
                status=FactStatus.IDENTITY_LOST,
                confidence=1.0,
            ),
        ),
    )

    assert view.terminal_byte_emit_sites_for_block(143) == ()


def test_stale_return_carrier_hazards_ignore_unrelated_or_incomplete_fact() -> None:
    unrelated = FactObservation(
        fact_id="return:unrelated",
        kind="ReturnCarrierFact",
        semantic_key="return:unrelated:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        source_ea=0x401000,
        payload={
            "upstream_writer_block_serial": 94,
            "upstream_writer_ea": 0x401020,
            "upstream_writer_var_refs": ["228"],
        },
    )
    incomplete = FactObservation(
        fact_id="return:incomplete",
        kind="ReturnCarrierFact",
        semantic_key="return:incomplete:key",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        source_ea=0x401000,
        payload={
            "upstream_writer_block_serial": 93,
            "upstream_writer_ea": 0x401030,
        },
    )
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(unrelated, incomplete),
        mappings=(
            FactMapping(
                source_fact_id="return:unrelated",
                source_maturity="MMAT_LOCOPT",
                target_maturity="MMAT_GLBOPT1",
                status=FactStatus.IDENTITY_LOST,
                confidence=1.0,
            ),
            FactMapping(
                source_fact_id="return:incomplete",
                source_maturity="MMAT_LOCOPT",
                target_maturity="MMAT_GLBOPT1",
                status=FactStatus.IDENTITY_LOST,
                confidence=1.0,
            ),
        ),
    )

    assert view.stale_return_carrier_hazards_for_block(93) == ()
