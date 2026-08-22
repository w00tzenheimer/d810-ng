"""Strict parsing tests for the durable analysis-phase witness."""

from __future__ import annotations

import json

import pytest

from d810.backends.ida.native_patch.phase_schema import (
    PhaseWitnessError,
    parse_analysis_phase_witness,
)
from d810.transforms.native_patch_plan import (
    NativeAddressRange,
    NativeCertificate,
    NativeCertificateState,
    NativeDatabaseIdentity,
    NativeFunctionIdentity,
)


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


def test_phase_parser_rejects_incomplete_reverse_schedule() -> None:
    payload = _payload()
    payload["reverse_schedule"] = [payload["reverse_schedule"][0]]  # type: ignore[index]

    with pytest.raises(PhaseWitnessError, match="schedule"):
        parse_analysis_phase_witness(_token(payload))


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
