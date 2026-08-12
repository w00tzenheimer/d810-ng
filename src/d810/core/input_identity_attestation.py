"""Portable, fail-closed recovery of a previously attested input identity.

The types in this module intentionally contain no IDA, filesystem, or
persistence knowledge.  A live backend collects current evidence and supplies
an IDB-local attestation; this module decides whether that evidence can
restore a native input SHA and whether external SHA-bound authority is allowed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
import uuid


_SCHEMA_VERSION = 1
_PROVENANCE_CAPTURED_FROM_IDA = "captured_from_ida"
_PROVENANCE_RECOVERED = "recovered_from_d810_attestation"


class InputIdentityRecoveryStatus(str, Enum):
    """Every identity decision a live backend can report."""

    LOADER_SHA_CAPTURED = "loader_sha_captured"
    RECOVERY_DISABLED = "recovery_disabled"
    ATTESTATION_MISSING = "attestation_missing"
    ATTESTATION_MALFORMED = "attestation_malformed"
    ATTESTATION_MISMATCH = "attestation_mismatch"
    RECOVERED_LOCAL_ONLY = "recovered_local_only"
    RECOVERED_FILE_HASH_VERIFIED = "recovered_file_hash_verified"
    INPUT_FILE_HASH_MISMATCH = "input_file_hash_mismatch"


def _normalized_sha256(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a SHA-256 string")
    normalized = value.lower().removeprefix("sha256:")
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"{field} must contain 64 hexadecimal digits")
    return normalized


def _normalized_digest(value: object, *, field: str) -> str:
    return "sha256:" + _normalized_sha256(value, field=field)


def _require_int(value: object, *, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer")
    if value < minimum:
        raise ValueError(f"{field} must be >= {minimum}")
    return int(value)


def _require_text(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value.strip()


@dataclass(frozen=True, slots=True)
class CurrentInputIdentityEvidence:
    """Current IDB characteristics needed to validate one function identity."""

    idb_creation_time: int
    processor: str
    bitness: int
    imagebase: int
    segment_map_digest: str
    function_rva: int
    function_fingerprint: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "idb_creation_time",
            _require_int(self.idb_creation_time, field="idb_creation_time"),
        )
        object.__setattr__(self, "processor", _require_text(self.processor, field="processor"))
        if self.bitness not in {16, 32, 64}:
            raise ValueError("bitness must be one of 16, 32, or 64")
        object.__setattr__(self, "bitness", int(self.bitness))
        object.__setattr__(
            self,
            "imagebase",
            _require_int(self.imagebase, field="imagebase"),
        )
        object.__setattr__(
            self,
            "segment_map_digest",
            _normalized_digest(self.segment_map_digest, field="segment_map_digest"),
        )
        object.__setattr__(
            self,
            "function_rva",
            _require_int(self.function_rva, field="function_rva"),
        )
        object.__setattr__(
            self,
            "function_fingerprint",
            _normalized_digest(self.function_fingerprint, field="function_fingerprint"),
        )


@dataclass(frozen=True, slots=True)
class InputIdentityAttestation:
    """Versioned input identity captured from a valid IDA loader SHA."""

    database_uuid: str
    input_sha256: str
    input_size: int
    idb_creation_time: int
    processor: str
    bitness: int
    imagebase: int
    segment_map_digest: str
    function_fingerprints: tuple[tuple[int, str], ...]
    provenance: str = _PROVENANCE_CAPTURED_FROM_IDA

    def __post_init__(self) -> None:
        try:
            normalized_uuid = str(uuid.UUID(str(self.database_uuid)))
        except (AttributeError, TypeError, ValueError) as error:
            raise ValueError("database_uuid must be a UUID") from error
        object.__setattr__(self, "database_uuid", normalized_uuid)
        object.__setattr__(
            self,
            "input_sha256",
            _normalized_sha256(self.input_sha256, field="input_sha256"),
        )
        object.__setattr__(
            self,
            "input_size",
            _require_int(self.input_size, field="input_size"),
        )
        object.__setattr__(
            self,
            "idb_creation_time",
            _require_int(self.idb_creation_time, field="idb_creation_time"),
        )
        object.__setattr__(self, "processor", _require_text(self.processor, field="processor"))
        if self.bitness not in {16, 32, 64}:
            raise ValueError("bitness must be one of 16, 32, or 64")
        object.__setattr__(self, "bitness", int(self.bitness))
        object.__setattr__(self, "imagebase", _require_int(self.imagebase, field="imagebase"))
        object.__setattr__(
            self,
            "segment_map_digest",
            _normalized_digest(self.segment_map_digest, field="segment_map_digest"),
        )
        raw_functions = tuple(self.function_fingerprints)
        normalized_functions: list[tuple[int, str]] = []
        for item in raw_functions:
            if not isinstance(item, tuple) or len(item) != 2:
                raise TypeError("function_fingerprints entries must be (rva, fingerprint)")
            rva, fingerprint = item
            normalized_functions.append(
                (
                    _require_int(rva, field="function_rva"),
                    _normalized_digest(fingerprint, field="function_fingerprint"),
                )
            )
        normalized_functions.sort()
        if not normalized_functions:
            raise ValueError("function_fingerprints must not be empty")
        if len({rva for rva, _fingerprint in normalized_functions}) != len(
            normalized_functions
        ):
            raise ValueError("function_fingerprints must use unique RVAs")
        object.__setattr__(self, "function_fingerprints", tuple(normalized_functions))
        if self.provenance != _PROVENANCE_CAPTURED_FROM_IDA:
            raise ValueError("attestation provenance must be captured_from_ida")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": _SCHEMA_VERSION,
            "database_uuid": self.database_uuid,
            "input_sha256": self.input_sha256,
            "input_size": self.input_size,
            "idb_creation_time": self.idb_creation_time,
            "processor": self.processor,
            "bitness": self.bitness,
            "imagebase": self.imagebase,
            "segment_map_digest": self.segment_map_digest,
            "function_fingerprints": [
                {"function_rva": rva, "function_fingerprint": fingerprint}
                for rva, fingerprint in self.function_fingerprints
            ],
            "provenance": self.provenance,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> InputIdentityAttestation:
        if not isinstance(payload, Mapping):
            raise TypeError("input identity attestation must be a mapping")
        expected = {
            "schema_version",
            "database_uuid",
            "input_sha256",
            "input_size",
            "idb_creation_time",
            "processor",
            "bitness",
            "imagebase",
            "segment_map_digest",
            "function_fingerprints",
            "provenance",
        }
        actual = set(payload)
        if actual != expected:
            raise ValueError(
                "input identity attestation fields mismatch: "
                f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
            )
        if payload["schema_version"] != _SCHEMA_VERSION:
            raise ValueError(
                "input identity attestation schema_version mismatch: "
                f"{payload['schema_version']!r}"
            )
        entries = payload["function_fingerprints"]
        if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
            raise TypeError("function_fingerprints must be a sequence")
        fingerprints: list[tuple[int, str]] = []
        for entry in entries:
            if not isinstance(entry, Mapping) or set(entry) != {
                "function_rva",
                "function_fingerprint",
            }:
                raise ValueError("function_fingerprints entries have invalid fields")
            fingerprints.append(
                (
                    _require_int(entry["function_rva"], field="function_rva"),
                    _normalized_digest(
                        entry["function_fingerprint"],
                        field="function_fingerprint",
                    ),
                )
            )
        return cls(
            database_uuid=payload["database_uuid"],
            input_sha256=payload["input_sha256"],
            input_size=payload["input_size"],
            idb_creation_time=payload["idb_creation_time"],
            processor=payload["processor"],
            bitness=payload["bitness"],
            imagebase=payload["imagebase"],
            segment_map_digest=payload["segment_map_digest"],
            function_fingerprints=tuple(fingerprints),
            provenance=payload["provenance"],
        )

    def first_mismatch(self, current: CurrentInputIdentityEvidence) -> str | None:
        if not isinstance(current, CurrentInputIdentityEvidence):
            raise TypeError("current evidence must be CurrentInputIdentityEvidence")
        for field in (
            "idb_creation_time",
            "processor",
            "bitness",
            "imagebase",
            "segment_map_digest",
        ):
            if getattr(self, field) != getattr(current, field):
                return field
        fingerprints = dict(self.function_fingerprints)
        expected = fingerprints.get(current.function_rva)
        if expected is None:
            return "function_rva"
        if expected != current.function_fingerprint:
            return "function_fingerprint"
        return None


@dataclass(frozen=True, slots=True)
class InputIdentityResolution:
    """The sole authority for identity provenance and external-evidence use."""

    status: InputIdentityRecoveryStatus
    input_identity: str | None
    provenance: str | None
    external_evidence_allowed: bool
    mismatch_field: str | None = None
    database_uuid: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, InputIdentityRecoveryStatus):
            raise TypeError("status must be InputIdentityRecoveryStatus")
        if self.input_identity is not None:
            object.__setattr__(
                self,
                "input_identity",
                _normalized_digest(self.input_identity, field="input_identity"),
            )
        if self.external_evidence_allowed and self.input_identity is None:
            raise ValueError("external evidence requires an input identity")
        if self.database_uuid is not None:
            if not isinstance(self.database_uuid, str) or not self.database_uuid.strip():
                raise ValueError("database_uuid must be a non-empty string when set")
            object.__setattr__(self, "database_uuid", self.database_uuid.strip())

    @property
    def reason(self) -> str:
        return (
            self.status.value
            if self.mismatch_field is None
            else f"{self.status.value}:{self.mismatch_field}"
        )


def _abstain(
    status: InputIdentityRecoveryStatus,
    *,
    mismatch_field: str | None = None,
) -> InputIdentityResolution:
    return InputIdentityResolution(
        status=status,
        input_identity=None,
        provenance=None,
        external_evidence_allowed=False,
        mismatch_field=mismatch_field,
    )


def resolve_attested_input_identity(
    *,
    loader_sha256: str | None,
    allow_recovery: bool,
    attestation: InputIdentityAttestation | None,
    current: CurrentInputIdentityEvidence,
    input_file_exists: bool,
    input_file_sha256: str | None,
) -> InputIdentityResolution:
    """Resolve normal or attested identity without inventing a fallback."""

    if loader_sha256 is not None:
        return InputIdentityResolution(
            status=InputIdentityRecoveryStatus.LOADER_SHA_CAPTURED,
            input_identity="sha256:"
            + _normalized_sha256(loader_sha256, field="loader_sha256"),
            provenance=_PROVENANCE_CAPTURED_FROM_IDA,
            external_evidence_allowed=True,
        )
    if not allow_recovery:
        return _abstain(InputIdentityRecoveryStatus.RECOVERY_DISABLED)
    if attestation is None:
        return _abstain(InputIdentityRecoveryStatus.ATTESTATION_MISSING)
    mismatch = attestation.first_mismatch(current)
    if mismatch is not None:
        return _abstain(
            InputIdentityRecoveryStatus.ATTESTATION_MISMATCH,
            mismatch_field=mismatch,
        )
    if not input_file_exists:
        return InputIdentityResolution(
            status=InputIdentityRecoveryStatus.RECOVERED_LOCAL_ONLY,
            input_identity="sha256:" + attestation.input_sha256,
            provenance=_PROVENANCE_RECOVERED,
            external_evidence_allowed=False,
        )
    if input_file_sha256 is None or (
        _normalized_sha256(input_file_sha256, field="input_file_sha256")
        != attestation.input_sha256
    ):
        return _abstain(InputIdentityRecoveryStatus.INPUT_FILE_HASH_MISMATCH)
    return InputIdentityResolution(
        status=InputIdentityRecoveryStatus.RECOVERED_FILE_HASH_VERIFIED,
        input_identity="sha256:" + attestation.input_sha256,
        provenance=_PROVENANCE_RECOVERED,
        external_evidence_allowed=True,
    )


__all__ = [
    "CurrentInputIdentityEvidence",
    "InputIdentityAttestation",
    "InputIdentityRecoveryStatus",
    "InputIdentityResolution",
    "resolve_attested_input_identity",
]
