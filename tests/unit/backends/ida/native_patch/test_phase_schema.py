"""Strict parsing tests for the durable analysis-phase witness."""

from __future__ import annotations

import json
import dataclasses

import pytest

from d810.backends.ida.native_patch.phase_schema import (
    canonical_phase_item_state,
    make_analysis_phase_attestation,
    materialize_analysis_phase,
    PhaseWitnessError,
    _parse_global_state,
    parse_analysis_phase_attestation,
    parse_analysis_phase_witness,
)
from d810.backends.ida.native_patch.gateway import (
    NativePatchCertificationFailed,
    NativePatchGateway,
)
from d810.transforms.native_patch_plan import (
    NativeAddressRange,
    NativeCertificate,
    NativeCertificateState,
    NativeDatabaseIdentity,
    NativeFunctionIdentity,
)


def test_global_item_state_normalizes_data_snapshot_query_anchor() -> None:
    payload = {
        "bytes": "0000000000000000",
        "ea": 0x10F1,
        "flags": 0,
        "full_flags": [0] * 8,
        "head_ea": 0x1000,
        "name": "",
        "offset": 0xF1,
        "size": 8,
        "xrefs": [],
    }
    interior = "data:v2:" + json.dumps(payload, sort_keys=True, separators=(",", ":"))
    normalized = canonical_phase_item_state(interior, head_ea=0x1000)
    normalized_payload = json.loads(normalized.removeprefix("data:v2:"))

    assert normalized_payload["ea"] == 0x1000
    assert normalized_payload["offset"] == 0
    assert canonical_phase_item_state(normalized, head_ea=0x1000) == normalized
    interior_state = _parse_global_state(
        {"items": [[0x1000, 8, interior]], "xrefs": [], "extents": [[0x1000, 0x1008]]},
        "interior",
    )
    head_state = _parse_global_state(
        {"items": [[0x1000, 8, normalized]], "xrefs": [], "extents": [[0x1000, 0x1008]]},
        "head",
    )
    assert interior_state == head_state
def _xref(source: int = 0x1000, target: int = 0x1010) -> dict[str, object]:
    return {
        "source_ea": source,
        "target_ea": target,
        "xref_type": 21,
        "user_owned": False,
        "is_code": True,
    }


def _payload() -> dict[str, object]:
    before_xrefs = [_xref()]
    group = {
        "version": 1,
        "origin_data_state": (
            "data:v2:{\"bytes\":\"00000000000000000000000000000000\","
            "\"ea\":4096,\"flags\":0,\"full_flags\":[0,0,0,0,0,0,0,0,"
            "0,0,0,0,0,0,0,0],\"head_ea\":4096,\"name\":\"\","
            "\"offset\":0,\"size\":16,\"xrefs\":[{\"is_code\":true,"
            "\"source_ea\":4096,\"target_ea\":4112,"
            "\"user_owned\":false,\"xref_type\":21}]}"
        ),
        "group_targets": [4096],
        "before_items": [[4096, 4, "code:4"]],
        "after_items": [[4096, 4, "code:4"]],
        "before_xrefs": before_xrefs,
        "after_xrefs": before_xrefs,
        "reverse_before_xrefs": before_xrefs,
        "reverse_after_xrefs": [],
        "postconditions": [{"ea": 4096, "state": "item-xrefs:v2:test"}],
    }
    return {
        "version": 1,
        "groups": [group],
        "reverse_schedule": [
            {"head_ea": 4096, "kind": "group"},
            {
                "action_kind": "update_xref",
                "ea": 4096,
                "expected_after": "crefs:v1:test",
                "index": 0,
                "kind": "action",
            },
        ],
    }


def _token(payload: dict[str, object]) -> str:
    return "analysis-phase:v1:" + json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )


def test_phase_parser_returns_frozen_typed_witness() -> None:
    witness = parse_analysis_phase_witness(_token(_payload()))

    assert witness.version == 1
    assert witness.groups[0].group_targets == (0x1000,)
    assert witness.reverse_schedule[0].head_ea == 0x1000


def test_phase_parser_rejects_bool_as_integer() -> None:
    payload = _payload()
    payload["groups"][0]["group_targets"] = [True]  # type: ignore[index]

    with pytest.raises(PhaseWitnessError, match="integer"):
        parse_analysis_phase_witness(_token(payload))


def test_phase_parser_rejects_unknown_group_key() -> None:
    payload = _payload()
    payload["groups"][0]["unexpected"] = 1  # type: ignore[index]

    with pytest.raises(PhaseWitnessError, match="keys"):
        parse_analysis_phase_witness(_token(payload))


def test_phase_parser_rejects_overlapping_items() -> None:
    payload = _payload()
    payload["groups"][0]["after_items"] = [  # type: ignore[index]
        [0x1000, 8, "code:8"],
        [0x1004, 4, "code:4"],
    ]

    with pytest.raises(PhaseWitnessError, match="overlap"):
        parse_analysis_phase_witness(_token(payload))


def test_global_state_accepts_overlapping_carrier_extents_with_one_partition() -> None:
    """Carrier extents may overlap when an item crosses their boundary."""
    state = {
        "items": [[0x1000, 0x18, "unknown"]],
        "xrefs": [],
        "extents": [[0x1000, 0x1010], [0x1008, 0x1018]],
    }

    parsed = _parse_global_state(state, "state")

    assert tuple((extent.low, extent.high) for extent in parsed.extents) == (
        (0x1000, 0x1010),
        (0x1008, 0x1018),
    )


def test_analysis_attestation_round_trips_observed_state_and_authorization_hash() -> None:
    authorization = _token(_payload())
    phase = parse_analysis_phase_witness(authorization)
    observed = _parse_global_state(
        {
            "items": [[0x1000, 0x10, "unknown"]],
            "xrefs": [],
            "extents": [[0x1000, 0x1010]],
        },
        "observed",
    )

    token = make_analysis_phase_attestation(authorization, phase, observed, "tx")
    attestation = parse_analysis_phase_attestation(token)

    assert attestation.authorization_hash == __import__("hashlib").sha256(
        authorization.encode()
    ).hexdigest()
    assert attestation.observed_state == observed
    assert len(attestation.reverse_schedule) == len(phase.reverse_schedule)
    assert attestation.reverse_schedule == materialize_analysis_phase(
        phase, observed
    ).reverse_schedule


def test_analysis_attestation_rejects_authorization_hash_not_bound_to_nested_phase() -> None:
    authorization = _token(_payload())
    phase = parse_analysis_phase_witness(authorization)
    observed = _parse_global_state(
        {"items": [[0x1000, 0x10, "unknown"]], "xrefs": [], "extents": [[0x1000, 0x1010]]},
        "observed",
    )
    token = make_analysis_phase_attestation(authorization, phase, observed, "tx")
    payload = json.loads(token.removeprefix("analysis-attestation:v1:"))
    payload["authorization_hash"] = "0" * 64
    tampered = "analysis-attestation:v1:" + json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )

    with pytest.raises(PhaseWitnessError, match="authorization hash"):
        parse_analysis_phase_attestation(tampered)


def test_analysis_attestation_rejects_unsupported_lifecycle_cut() -> None:
    authorization = _token(_payload())
    phase = parse_analysis_phase_witness(authorization)
    observed = _parse_global_state(
        {"items": [[0x1000, 0x10, "unknown"]], "xrefs": [], "extents": [[0x1000, 0x1010]]},
        "observed",
    )
    token = make_analysis_phase_attestation(authorization, phase, observed, "tx")
    payload = json.loads(token.removeprefix("analysis-attestation:v1:"))
    payload["lifecycle_cut"] = "other"
    tampered = "analysis-attestation:v1:" + json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )

    with pytest.raises(PhaseWitnessError, match="lifecycle_cut"):
        parse_analysis_phase_attestation(tampered)


def test_analysis_attestation_rejects_tampered_materialized_schedule() -> None:
    authorization = _token(_payload())
    phase = parse_analysis_phase_witness(authorization)
    observed = _parse_global_state(
        {"items": [[0x1000, 0x10, "unknown"]], "xrefs": [], "extents": [[0x1000, 0x1010]]},
        "observed",
    )
    token = make_analysis_phase_attestation(authorization, phase, observed, "tx")
    payload = json.loads(token.removeprefix("analysis-attestation:v1:"))
    payload["reverse_schedule"][0]["head_ea"] = 0x2000
    tampered = "analysis-attestation:v1:" + json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )

    with pytest.raises(PhaseWitnessError, match="schedule"):
        parse_analysis_phase_attestation(tampered)


@pytest.mark.parametrize("state", ["item-xrefs:v2:bad", "data:v1:{}", "code:2"])
def test_global_state_rejects_unsupported_or_mismatched_item_state(state: str) -> None:
    with pytest.raises(PhaseWitnessError, match="(unsupported|code size|data)"):
        _parse_global_state(
            {"items": [[0x1000, 4, state]], "xrefs": [], "extents": [[0x1000, 0x1004]]},
            "state",
        )


def test_global_state_rejects_xref_outside_declared_extents() -> None:
    with pytest.raises(PhaseWitnessError, match="does not touch"):
        _parse_global_state(
            {
                "items": [[0x1000, 4, "unknown"]],
                "xrefs": [_xref(0x2000, 0x3000)],
                "extents": [[0x1000, 0x1004]],
            },
            "state",
        )


@pytest.mark.parametrize(
    ("items", "extents", "match"),
    (
        (
            [[0x1000, 4, "unknown"], [0x1008, 4, "unknown"]],
            [[0x1000, 0x1010]],
            "cover extents",
        ),
        (
            [[0x0FF0, 4, "unknown"], [0x1000, 0x10, "unknown"]],
            [[0x1000, 0x1010]],
            "outside extents",
        ),
        (
            [[0x1000, 0x10, "unknown"]],
            [[0x1010, 0x1020]],
            "cover extents",
        ),
    ),
)
def test_global_state_rejects_item_gaps_and_items_outside_extent_union(
    items, extents, match
) -> None:
    with pytest.raises(PhaseWitnessError, match=match):
        _parse_global_state({"items": items, "xrefs": [], "extents": extents}, "state")


@pytest.mark.parametrize(
    "extents",
    (
        [[0x1010, 0x1000]],
        [[0x1000, 0x1010], [0x1000, 0x1010]],
        [[0x1010, 0x1020], [0x1000, 0x1010]],
    ),
)
def test_global_state_rejects_reversed_and_duplicate_extents(extents) -> None:
    with pytest.raises(PhaseWitnessError, match="extents"):
        _parse_global_state(
            {"items": [[0x1000, 0x10, "unknown"]], "xrefs": [], "extents": extents},
            "state",
        )


def test_phase_parser_rejects_incomplete_reverse_schedule() -> None:
    payload = _payload()
    payload["reverse_schedule"] = [payload["reverse_schedule"][0]]  # type: ignore[index]

    with pytest.raises(PhaseWitnessError, match="schedule"):
        parse_analysis_phase_witness(_token(payload))


def test_phase_parser_preserves_global_action_index_gaps() -> None:
    payload = _payload()
    payload["reverse_schedule"][1]["index"] = 65  # type: ignore[index]

    witness = parse_analysis_phase_witness(_token(payload))

    assert witness.reverse_schedule[1].index == 65


def _certificate(*, schema_version: int, witness: str | None) -> NativeCertificate:
    return NativeCertificate(
        certificate_id="cert",
        schema_version=schema_version,
        database_identity=NativeDatabaseIdentity(
            idb_uuid="idb", input_file_hash="file", processor="metapc",
            bitness=64, image_base=0, database_path_hash="path",
        ),
        function_identity=NativeFunctionIdentity(
            entry_ea=0x1000,
            chunk_ranges=(NativeAddressRange(0x1000, 0x1010),),
            inherited_bytes_hash="bytes",
        ),
        inherited_fingerprint="before",
        normalized_fingerprint="after",
        target_cfg_fingerprint="cfg",
        native_origin_map_fingerprint="origin",
        semantic_plan_hash="semantic",
        native_plan_hash="plan",
        metadata_target_fingerprint="metadata",
        d810_version="test",
        authorization_class="lifting_normalization",
        state=NativeCertificateState.APPLIED,
        certified_at=0,
        analysis_phase_witness=witness,
    )


def test_certificate_schema_four_requires_phase_witness() -> None:
    with pytest.raises(ValueError, match="schema 4"):
        _certificate(schema_version=4, witness=None)


def test_certificate_schema_three_rejects_phase_witness() -> None:
    with pytest.raises(ValueError, match="schema 3"):
        _certificate(schema_version=3, witness=_token(_payload()))


def test_certificate_schema_three_rejects_phase_hashes() -> None:
    certificate = _certificate(schema_version=3, witness=None)
    with pytest.raises(ValueError, match="phase hashes"):
        dataclasses.replace(
            certificate,
            analysis_phase_authorization_hash="0" * 64,
        )


def test_certificate_payload_rejects_non_string_phase_hash() -> None:
    from d810.transforms.native_patch_plan import certificate_from_payload, certificate_to_payload

    payload = certificate_to_payload(_certificate(schema_version=3, witness=None))
    payload["analysis_phase_authorization_hash"] = 42
    with pytest.raises(TypeError, match="analysis_phase_authorization_hash"):
        certificate_from_payload(payload)


def test_gateway_rejects_v1_phase_authority() -> None:
    from . import _plan_fixtures as fixtures

    plan = dataclasses.replace(
        fixtures.plan(), analysis_phase_witness=_token(_payload())
    )
    with pytest.raises(NativePatchCertificationFailed, match="unsupported"):
        NativePatchGateway._parse_analysis_phase_witness(plan)
