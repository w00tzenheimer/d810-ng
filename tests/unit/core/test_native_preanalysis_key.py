from __future__ import annotations

import json

import pytest

from d810.core.native_preanalysis_key import (
    NativePreanalysisKey,
    NativePreanalysisKeyMismatch,
)


def _key(**overrides: object) -> NativePreanalysisKey:
    values: dict[str, object] = {
        "input_identity": "sha256:input-a",
        "processor": "metapc",
        "bitness": 64,
        "function_rva": 0xD200,
        "function_fingerprint": "sha256:function-a",
        "profile_fingerprint": "sha256:profile-a",
        "sdk_fingerprint": "hexrays:9.3.0.250604",
    }
    values.update(overrides)
    return NativePreanalysisKey(**values)


def test_key_equality_uses_every_identity_component() -> None:
    assert _key() == _key()
    assert _key(input_identity="sha256:input-b") != _key()
    assert _key(profile_fingerprint="sha256:profile-b") != _key()
    assert _key(sdk_fingerprint="hexrays:9.4") != _key()


def test_key_serialization_is_deterministic_and_round_trips() -> None:
    key = _key()

    encoded = key.to_json()

    assert encoded == (
        '{"bitness":64,"function_fingerprint":"sha256:function-a",'
        '"function_rva":53760,"input_identity":"sha256:input-a",'
        '"processor":"metapc","profile_fingerprint":"sha256:profile-a",'
        '"schema_version":1,"sdk_fingerprint":"hexrays:9.3.0.250604"}'
    )
    assert NativePreanalysisKey.from_json(encoded) == key
    assert NativePreanalysisKey.from_dict(json.loads(encoded)) == key


def test_key_mismatch_reports_distinct_components() -> None:
    expected = _key()
    actual = _key(input_identity="sha256:input-b", sdk_fingerprint="hexrays:9.4")

    with pytest.raises(NativePreanalysisKeyMismatch) as error:
        expected.require_match(actual)

    assert error.value.fields == ("input_identity", "sdk_fingerprint")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("input_identity", ""),
        ("processor", "unknown"),
        ("function_fingerprint", "placeholder"),
        ("profile_fingerprint", "unset"),
        ("sdk_fingerprint", "n/a"),
    ],
)
def test_key_rejects_missing_or_placeholder_identities(field: str, value: str) -> None:
    with pytest.raises(ValueError, match=field):
        _key(**{field: value})


@pytest.mark.parametrize("bitness", [0, 8, 128])
def test_key_rejects_unsupported_bitness(bitness: int) -> None:
    with pytest.raises(ValueError, match="bitness"):
        _key(bitness=bitness)


def test_key_rejects_negative_function_rva() -> None:
    with pytest.raises(ValueError, match="function_rva"):
        _key(function_rva=-1)


def test_deserialization_rejects_schema_or_shape_mismatch() -> None:
    payload = json.loads(_key().to_json())
    payload["schema_version"] = 2
    with pytest.raises(ValueError, match="schema_version"):
        NativePreanalysisKey.from_dict(payload)

    payload = json.loads(_key().to_json())
    payload["extra"] = "not accepted"
    with pytest.raises(ValueError, match="fields"):
        NativePreanalysisKey.from_dict(payload)
