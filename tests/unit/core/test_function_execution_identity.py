"""Tests for portable function and MBA observation identity."""

from __future__ import annotations

from uuid import UUID

import pytest

from d810.core.execution_journal import DecompilationSessionId
from d810.core.input_identity_attestation import (
    InputIdentityRecoveryStatus,
    InputIdentityResolution,
)
from d810.core.plugins import PluginIdentity
from d810.core.function_execution_identity import (
    FunctionExecutionIdentity,
    MbaObservationContext,
)
from d810.ir.maturity import IRMaturity


SHA = "a" * 64
DATABASE_UUID = "12345678-1234-5678-1234-567812345678"
SESSION = DecompilationSessionId("session-1")
PLUGIN = PluginIdentity("cobra", "d810-cobra", "1.0", "test")


def _identity(**overrides: object) -> FunctionExecutionIdentity:
    values: dict[str, object] = {
        "input_identity": f"sha256:{SHA}",
        "input_identity_provenance": "verified_loader_sha256",
        "external_evidence_allowed": True,
        "database_uuid": DATABASE_UUID,
        "database_identity": "sample.i64",
        "function_ea": 0x401000,
        "function_rva": 0x1000,
        "function_fingerprint": f"sha256:{'b' * 64}",
        "decompilation_session_id": SESSION,
        "top_level_epoch": 2,
        "maturity": IRMaturity.CANONICAL,
        "evidence_generation": 3,
    }
    values.update(overrides)
    return FunctionExecutionIdentity(**values)


def test_verified_sha_is_normalized_and_external_eligible() -> None:
    identity = _identity(input_identity=f"SHA256:{SHA.upper()}")

    assert identity.input_identity == f"sha256:{SHA}"
    assert identity.external_evidence_allowed is True
    assert identity.function_fingerprint == f"sha256:{'b' * 64}"


def test_maturity_is_canonicalized_across_enum_and_reload_shaped_string() -> None:
    from_enum = _identity()
    from_string = _identity(maturity="ir.canonical")

    assert from_enum.maturity == from_string.maturity == "ir.canonical"
    assert from_enum == from_string
    assert from_enum.to_json() == from_string.to_json()


def test_mutable_maturity_impostor_is_rejected() -> None:
    class MutableMaturity:
        value = "ir.canonical"

    with pytest.raises((TypeError, ValueError)):
        _identity(maturity=MutableMaturity())


def test_idb_local_identity_is_normalized_and_not_external_eligible() -> None:
    identity = _identity(
        input_identity=f"idb-local:{UUID(DATABASE_UUID).hex}",
        input_identity_provenance="current_idb",
        external_evidence_allowed=False,
    )

    assert identity.input_identity == f"idb-local:{DATABASE_UUID}"
    assert identity.external_evidence_allowed is False


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("input_identity", "sha256:not-a-digest"),
        ("input_identity_provenance", ""),
        ("database_uuid", "not-a-uuid"),
        ("database_identity", ""),
        ("function_ea", -1),
        ("function_rva", -1),
        ("function_fingerprint", "unknown"),
        ("decompilation_session_id", ""),
        ("top_level_epoch", 0),
        ("maturity", "not-a-maturity"),
        ("evidence_generation", -1),
    ),
)
def test_invalid_identity_values_fail_closed(field: str, value: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        _identity(**{field: value})


def test_function_identity_rejects_bad_address_function_anchor() -> None:
    with pytest.raises(ValueError, match="function_ea must not be BADADDR"):
        _identity(function_ea=(1 << 64) - 1)


def test_external_evidence_requires_verified_sha_identity() -> None:
    with pytest.raises(ValueError, match="external evidence"):
        _identity(
            input_identity=f"idb-local:{DATABASE_UUID}",
            input_identity_provenance="current_idb",
            external_evidence_allowed=True,
        )


@pytest.mark.parametrize(
    "provenance",
    ("verified_loader_sha256", "captured_from_ida", "recovered_from_d810_attestation"),
)
def test_external_sha_requires_verified_provenance(provenance: str) -> None:
    identity = _identity(input_identity_provenance=provenance)

    assert identity.external_evidence_allowed is True


def test_local_identity_requires_local_provenance() -> None:
    with pytest.raises(ValueError, match="provenance"):
        _identity(
            input_identity=f"idb-local:{DATABASE_UUID}",
            input_identity_provenance="verified_loader_sha256",
            external_evidence_allowed=False,
        )


def test_verified_sha_cannot_claim_local_provenance() -> None:
    with pytest.raises(ValueError, match="provenance"):
        _identity(
            input_identity=f"sha256:{SHA}",
            input_identity_provenance="current_idb",
            external_evidence_allowed=True,
        )


def test_unverified_sha_cannot_claim_verified_provenance() -> None:
    with pytest.raises(ValueError, match="provenance"):
        _identity(
            input_identity=f"sha256:{SHA}",
            input_identity_provenance="verified_loader_sha256",
            external_evidence_allowed=False,
        )


def test_unrecognized_sha_provenance_cannot_be_retained_locally() -> None:
    with pytest.raises(ValueError, match="verified SHA"):
        _identity(
            input_identity=f"sha256:{SHA}",
            input_identity_provenance="review_unverified",
            external_evidence_allowed=False,
        )


def test_local_identity_database_uuid_must_agree() -> None:
    with pytest.raises(ValueError, match="database UUID"):
        _identity(
            input_identity=f"idb-local:{DATABASE_UUID}",
            input_identity_provenance="current_idb",
            external_evidence_allowed=False,
            database_uuid="87654321-4321-8765-4321-876543218765",
        )


def test_bool_is_not_accepted_as_numeric_identity() -> None:
    with pytest.raises(TypeError):
        _identity(function_ea=True)


def test_function_ea_must_not_precede_function_rva() -> None:
    with pytest.raises(ValueError, match="function EA"):
        _identity(function_ea=0x1000, function_rva=0x2000)


def test_session_id_is_reused_as_serializable_value() -> None:
    identity = _identity()

    assert identity.decompilation_session_id == SESSION.value
    assert identity.to_dict()["decompilation_session_id"] == SESSION.value
    assert '"maturity":"ir.canonical"' in identity.to_json()


def test_mba_context_requires_block_anchor_when_serial_is_present() -> None:
    with pytest.raises(ValueError, match="block EA"):
        MbaObservationContext(
            function_identity=_identity(),
            plugin_identity=PLUGIN,
            instruction_ea=0x401005,
            block_serial=7,
            block_ea=None,
        )


def test_mba_context_allows_block_ea_without_serial_explicitly() -> None:
    """A physical EA may be retained without a transient Hex-Rays serial."""
    context = MbaObservationContext(
        function_identity=_identity(),
        plugin_identity=PLUGIN,
        instruction_ea=0x401005,
        block_serial=None,
        block_ea=0x401000,
    )

    assert context.block_ea == 0x401000
    assert context.block_identity is None


def test_mba_context_rejects_bad_address_block_anchor() -> None:
    with pytest.raises(ValueError, match="block EA"):
        MbaObservationContext(
            function_identity=_identity(),
            plugin_identity=PLUGIN,
            instruction_ea=0x401005,
            block_serial=7,
            block_ea=(1 << 64) - 1,
        )


def test_mba_context_rejects_bad_address_instruction_anchor() -> None:
    with pytest.raises(ValueError, match="instruction EA"):
        MbaObservationContext(
            function_identity=_identity(),
            plugin_identity=PLUGIN,
            instruction_ea=(1 << 64) - 1,
        )


def test_mba_context_rejects_bad_address_block_anchor_without_serial() -> None:
    with pytest.raises(ValueError, match="block EA"):
        MbaObservationContext(
            function_identity=_identity(),
            plugin_identity=PLUGIN,
            instruction_ea=0x401005,
            block_ea=(1 << 64) - 1,
        )


def test_mba_context_is_immutable_and_validates_anchors() -> None:
    context = MbaObservationContext(
        function_identity=_identity(),
        plugin_identity=PLUGIN,
        instruction_ea=0x401005,
        block_serial=7,
        block_ea=0x401000,
    )

    assert context.to_dict()["block_identity"] == "blk7@0x401000"
    with pytest.raises((AttributeError, TypeError)):
        context.instruction_ea = 0x401006  # type: ignore[misc]


def test_context_rejects_invalid_plugin_and_instruction_anchor() -> None:
    with pytest.raises(TypeError):
        MbaObservationContext(
            function_identity=_identity(),
            plugin_identity="cobra",  # type: ignore[arg-type]
            instruction_ea=0x401005,
        )
    with pytest.raises(ValueError):
        MbaObservationContext(
            function_identity=_identity(),
            plugin_identity=PLUGIN,
            instruction_ea=-1,
        )
    with pytest.raises(ValueError, match="plugin name"):
        MbaObservationContext(
            function_identity=_identity(),
            plugin_identity=PluginIdentity("", "d810-cobra", "1.0", "test"),
            instruction_ea=0x401005,
        )
    with pytest.raises(ValueError, match="plugin origin"):
        MbaObservationContext(
            function_identity=_identity(),
            plugin_identity=PluginIdentity("cobra", "d810-cobra", "1.0", " runtime "),
            instruction_ea=0x401005,
        )
    with pytest.raises(ValueError, match="plugin distribution"):
        MbaObservationContext(
            function_identity=_identity(),
            plugin_identity=PluginIdentity("cobra", " d810-cobra ", "1.0", "test"),
            instruction_ea=0x401005,
        )
    with pytest.raises(ValueError, match="plugin version"):
        MbaObservationContext(
            function_identity=_identity(),
            plugin_identity=PluginIdentity("cobra", "d810-cobra", " 1.0 ", "test"),
            instruction_ea=0x401005,
        )


def test_identity_resolution_accepts_verified_authority_shape() -> None:
    resolution = InputIdentityResolution(
        status=InputIdentityRecoveryStatus.LOADER_SHA_CAPTURED,
        input_identity=f"sha256:{SHA}",
        provenance="verified_loader_sha256",
        external_evidence_allowed=True,
        database_uuid=DATABASE_UUID,
    )

    assert resolution.external_evidence_allowed is True
