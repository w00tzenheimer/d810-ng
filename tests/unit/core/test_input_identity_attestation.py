from __future__ import annotations

import pytest

from d810.core.input_identity_attestation import (
    CurrentInputIdentityEvidence,
    InputIdentityAttestation,
    InputIdentityRecoveryStatus,
    resolve_attested_input_identity,
)


_SHA_A = "a" * 64
_SHA_B = "b" * 64
_FUNCTION_A = "sha256:" + ("1" * 64)
_FUNCTION_B = "sha256:" + ("2" * 64)
_SEGMENTS = "sha256:" + ("3" * 64)


def _current(**overrides: object) -> CurrentInputIdentityEvidence:
    payload: dict[str, object] = {
        "idb_creation_time": 1700000000,
        "processor": "metapc",
        "bitness": 64,
        "imagebase": 0x140000000,
        "segment_map_digest": _SEGMENTS,
        "function_rva": 0x1234,
        "function_fingerprint": _FUNCTION_A,
    }
    payload.update(overrides)
    return CurrentInputIdentityEvidence(**payload)


def _attestation(**overrides: object) -> InputIdentityAttestation:
    payload: dict[str, object] = {
        "database_uuid": "60d2b1e4-0c0b-4cc5-9182-41d761e10013",
        "input_sha256": _SHA_A,
        "input_size": 8192,
        "idb_creation_time": 1700000000,
        "processor": "metapc",
        "bitness": 64,
        "imagebase": 0x140000000,
        "segment_map_digest": _SEGMENTS,
        "function_fingerprints": ((0x1234, _FUNCTION_A), (0x2345, _FUNCTION_B)),
        "provenance": "captured_from_ida",
    }
    payload.update(overrides)
    return InputIdentityAttestation(**payload)


def test_attestation_round_trips_with_exact_schema() -> None:
    attestation = _attestation()

    restored = InputIdentityAttestation.from_dict(attestation.to_dict())

    assert restored == attestation
    with pytest.raises(ValueError, match="fields mismatch"):
        InputIdentityAttestation.from_dict(
            {**attestation.to_dict(), "unexpected": "field"}
        )


def test_missing_loader_sha_is_disabled_by_default() -> None:
    resolution = resolve_attested_input_identity(
        loader_sha256=None,
        allow_recovery=False,
        attestation=_attestation(),
        current=_current(),
        input_file_exists=False,
        input_file_sha256=None,
    )

    assert resolution.status is InputIdentityRecoveryStatus.RECOVERY_DISABLED
    assert resolution.input_identity is None
    assert resolution.external_evidence_allowed is False


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("idb_creation_time", 1700000001),
        ("processor", "arm"),
        ("bitness", 32),
        ("imagebase", 0x400000),
        ("segment_map_digest", "sha256:" + ("4" * 64)),
        ("function_rva", 0x1235),
        ("function_fingerprint", "sha256:" + ("5" * 64)),
    ),
)
def test_attestation_mismatch_fails_closed(field: str, value: object) -> None:
    resolution = resolve_attested_input_identity(
        loader_sha256=None,
        allow_recovery=True,
        attestation=_attestation(),
        current=_current(**{field: value}),
        input_file_exists=False,
        input_file_sha256=None,
    )

    assert resolution.status is InputIdentityRecoveryStatus.ATTESTATION_MISMATCH
    assert resolution.mismatch_field == field
    assert resolution.input_identity is None
    assert resolution.external_evidence_allowed is False


def test_missing_function_attestation_fails_closed() -> None:
    resolution = resolve_attested_input_identity(
        loader_sha256=None,
        allow_recovery=True,
        attestation=_attestation(function_fingerprints=((0x2345, _FUNCTION_B),)),
        current=_current(),
        input_file_exists=False,
        input_file_sha256=None,
    )

    assert resolution.status is InputIdentityRecoveryStatus.ATTESTATION_MISMATCH
    assert resolution.mismatch_field == "function_rva"


def test_matching_attestation_recovers_local_only_without_input_file() -> None:
    resolution = resolve_attested_input_identity(
        loader_sha256=None,
        allow_recovery=True,
        attestation=_attestation(),
        current=_current(),
        input_file_exists=False,
        input_file_sha256=None,
    )

    assert resolution.status is InputIdentityRecoveryStatus.RECOVERED_LOCAL_ONLY
    assert resolution.input_identity == "sha256:" + _SHA_A
    assert resolution.provenance == "recovered_from_d810_attestation"
    assert resolution.external_evidence_allowed is False


def test_matching_attestation_enables_external_evidence_only_after_file_hash() -> None:
    resolution = resolve_attested_input_identity(
        loader_sha256=None,
        allow_recovery=True,
        attestation=_attestation(),
        current=_current(),
        input_file_exists=True,
        input_file_sha256=_SHA_A,
    )

    assert resolution.status is InputIdentityRecoveryStatus.RECOVERED_FILE_HASH_VERIFIED
    assert resolution.external_evidence_allowed is True


def test_existing_input_file_hash_mismatch_abstains() -> None:
    resolution = resolve_attested_input_identity(
        loader_sha256=None,
        allow_recovery=True,
        attestation=_attestation(),
        current=_current(),
        input_file_exists=True,
        input_file_sha256=_SHA_B,
    )

    assert resolution.status is InputIdentityRecoveryStatus.INPUT_FILE_HASH_MISMATCH
    assert resolution.input_identity is None
    assert resolution.external_evidence_allowed is False


def test_loader_sha_is_authoritative_without_recovery() -> None:
    resolution = resolve_attested_input_identity(
        loader_sha256=_SHA_B,
        allow_recovery=False,
        attestation=None,
        current=_current(),
        input_file_exists=False,
        input_file_sha256=None,
    )

    assert resolution.status is InputIdentityRecoveryStatus.LOADER_SHA_CAPTURED
    assert resolution.input_identity == "sha256:" + _SHA_B
    assert resolution.external_evidence_allowed is True
    assert resolution.provenance == "captured_from_ida"
