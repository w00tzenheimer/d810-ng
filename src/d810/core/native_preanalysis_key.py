"""Portable identity for native facts reused across decompilation maturities.

The value object is deliberately IDA-free.  Live loader/backend code must
derive every component from the current input, function, configuration, and
SDK before constructing it; this module supplies no fallback identity.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass

from d810.core.typing import ClassVar


_PLACEHOLDER_IDENTITIES = frozenset(
    {"", "n/a", "none", "null", "placeholder", "unknown", "unset"}
)


class NativePreanalysisKeyMismatch(ValueError):
    """Raised when portable evidence belongs to a different native key."""

    def __init__(
        self,
        expected: NativePreanalysisKey,
        actual: NativePreanalysisKey,
        fields: tuple[str, ...],
    ) -> None:
        self.expected = expected
        self.actual = actual
        self.fields = fields
        super().__init__("native preanalysis key mismatch: " + ", ".join(fields))


@dataclass(frozen=True, order=True, slots=True)
class NativePreanalysisKey:
    """Complete serializable identity for one function's native analysis."""

    input_identity: str
    processor: str
    bitness: int
    function_rva: int
    function_fingerprint: str
    profile_fingerprint: str
    sdk_fingerprint: str

    SCHEMA_VERSION: ClassVar[int] = 1
    _IDENTITY_FIELDS: ClassVar[tuple[str, ...]] = (
        "input_identity",
        "processor",
        "bitness",
        "function_rva",
        "function_fingerprint",
        "profile_fingerprint",
        "sdk_fingerprint",
    )

    def __post_init__(self) -> None:
        for field_name in (
            "input_identity",
            "processor",
            "function_fingerprint",
            "profile_fingerprint",
            "sdk_fingerprint",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str):
                raise TypeError(f"{field_name} must be a string")
            normalized = value.strip()
            if normalized.lower() in _PLACEHOLDER_IDENTITIES:
                raise ValueError(
                    f"{field_name} requires a real, non-placeholder identity"
                )
            object.__setattr__(self, field_name, normalized)

        if isinstance(self.bitness, bool) or not isinstance(self.bitness, int):
            raise TypeError("bitness must be an integer")
        if self.bitness not in {16, 32, 64}:
            raise ValueError("bitness must be one of 16, 32, or 64")
        if isinstance(self.function_rva, bool) or not isinstance(
            self.function_rva, int
        ):
            raise TypeError("function_rva must be an integer")
        if self.function_rva < 0:
            raise ValueError("function_rva must be non-negative")

    def to_dict(self) -> dict[str, int | str]:
        """Return the stable schema representation used by caches and logs."""
        return {
            "schema_version": self.SCHEMA_VERSION,
            "input_identity": self.input_identity,
            "processor": self.processor,
            "bitness": self.bitness,
            "function_rva": self.function_rva,
            "function_fingerprint": self.function_fingerprint,
            "profile_fingerprint": self.profile_fingerprint,
            "sdk_fingerprint": self.sdk_fingerprint,
        }

    def to_json(self) -> str:
        """Serialize deterministically without depending on field declaration order."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> NativePreanalysisKey:
        """Deserialize one exact schema; partial and extended keys fail closed."""
        if not isinstance(payload, Mapping):
            raise TypeError("native preanalysis key payload must be a mapping")
        expected_fields = {"schema_version", *cls._IDENTITY_FIELDS}
        actual_fields = set(payload)
        if actual_fields != expected_fields:
            missing = sorted(expected_fields - actual_fields)
            extra = sorted(actual_fields - expected_fields)
            raise ValueError(
                "native preanalysis key fields mismatch: "
                f"missing={missing} extra={extra}"
            )
        if payload["schema_version"] != cls.SCHEMA_VERSION:
            raise ValueError(
                "native preanalysis key schema_version mismatch: "
                f"{payload['schema_version']!r}"
            )
        return cls(**{name: payload[name] for name in cls._IDENTITY_FIELDS})  # type: ignore[arg-type]

    @classmethod
    def from_json(cls, payload: str) -> NativePreanalysisKey:
        """Deserialize the canonical JSON representation."""
        decoded = json.loads(payload)
        if not isinstance(decoded, dict):
            raise TypeError("native preanalysis key JSON must contain an object")
        return cls.from_dict(decoded)

    def mismatch_fields(self, other: NativePreanalysisKey) -> tuple[str, ...]:
        """Return identity components that differ in stable schema order."""
        if not isinstance(other, NativePreanalysisKey):
            raise TypeError("other must be a NativePreanalysisKey")
        return tuple(
            field_name
            for field_name in self._IDENTITY_FIELDS
            if getattr(self, field_name) != getattr(other, field_name)
        )

    def require_match(self, other: NativePreanalysisKey) -> None:
        """Reject evidence or bindings scoped to any different native input."""
        fields = self.mismatch_fields(other)
        if fields:
            raise NativePreanalysisKeyMismatch(self, other, fields)


__all__ = ["NativePreanalysisKey", "NativePreanalysisKeyMismatch"]
