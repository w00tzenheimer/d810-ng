"""Portable identity for one function execution and MBA observation."""

from __future__ import annotations

from dataclasses import dataclass
import json
from uuid import UUID

from d810.core.execution_journal import DecompilationSessionId
from d810.core.input_identity_attestation import (
    InputIdentityRecoveryStatus,
    InputIdentityResolution,
    local_idb_identity,
)
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.plugins import PluginIdentity


_PLACEHOLDER_IDENTITIES = frozenset(
    {"", "n/a", "none", "null", "placeholder", "unknown", "unset"}
)
_MATURITY_VALUES = frozenset(
    {
        "ir.lifted",
        "ir.canonical",
        "ir.local.optimized",
        "ir.call.modeled",
        "ir.global.analyzed",
        "ir.global.optimized",
        "ir.structured",
        "ir.variable.recovered",
    }
)


def _non_negative_int(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer")
    if value < 0:
        raise ValueError(f"{field} must be non-negative")
    return int(value)


def _positive_int(value: object, *, field: str) -> int:
    result = _non_negative_int(value, field=field)
    if result <= 0:
        raise ValueError(f"{field} must be positive")
    return result


def _text(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    result = value.strip()
    if not result or result.lower() in _PLACEHOLDER_IDENTITIES:
        raise ValueError(f"{field} must be a non-placeholder string")
    return result


def _normalize_input_identity(value: object) -> str:
    raw = _text(value, field="input_identity")
    if raw.lower().startswith("idb-local:"):
        return local_idb_identity(raw.removeprefix("idb-local:"))
    resolution = InputIdentityResolution(
        status=InputIdentityRecoveryStatus.LOADER_SHA_CAPTURED,
        input_identity=raw,
        provenance="function_execution_identity",
        external_evidence_allowed=False,
    )
    assert resolution.input_identity is not None  # validated by the value object
    return resolution.input_identity


def _normalize_uuid(value: object, *, field: str) -> str:
    raw = _text(value, field=field)
    try:
        return str(UUID(raw))
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError(f"{field} must be a UUID") from error


def _normalize_session_id(value: object) -> str:
    if isinstance(value, DecompilationSessionId):
        return _text(value.value, field="decompilation_session_id")
    return _text(value, field="decompilation_session_id")


def _normalize_maturity(value: object) -> object:
    normalized = getattr(value, "value", value)
    if not isinstance(normalized, str) or normalized not in _MATURITY_VALUES:
        raise ValueError("maturity must be a portable IRMaturity")
    return value


@dataclass(frozen=True, slots=True)
class FunctionExecutionIdentity:
    """Immutable, IDA-free identity for one function execution."""

    input_identity: str
    input_identity_provenance: str
    external_evidence_allowed: bool
    database_uuid: str
    database_identity: str
    function_ea: int
    function_rva: int
    function_fingerprint: str
    decompilation_session_id: str | DecompilationSessionId
    top_level_epoch: int
    maturity: object
    evidence_generation: int

    def __post_init__(self) -> None:
        input_identity = _normalize_input_identity(self.input_identity)
        object.__setattr__(self, "input_identity", input_identity)
        object.__setattr__(
            self,
            "input_identity_provenance",
            _text(self.input_identity_provenance, field="input_identity_provenance"),
        )
        if not isinstance(self.external_evidence_allowed, bool):
            raise TypeError("external_evidence_allowed must be a bool")
        if self.external_evidence_allowed and not input_identity.startswith("sha256:"):
            raise ValueError("external evidence requires a verified SHA identity")
        object.__setattr__(
            self,
            "database_uuid",
            _normalize_uuid(self.database_uuid, field="database_uuid"),
        )
        object.__setattr__(
            self,
            "database_identity",
            _text(self.database_identity, field="database_identity"),
        )
        object.__setattr__(
            self,
            "function_ea",
            _non_negative_int(self.function_ea, field="function_ea"),
        )
        object.__setattr__(
            self,
            "function_rva",
            _non_negative_int(self.function_rva, field="function_rva"),
        )
        if self.function_ea < self.function_rva:
            raise ValueError("function EA cannot precede its function RVA")
        object.__setattr__(
            self,
            "function_fingerprint",
            _text(self.function_fingerprint, field="function_fingerprint"),
        )
        object.__setattr__(
            self,
            "decompilation_session_id",
            _normalize_session_id(self.decompilation_session_id),
        )
        object.__setattr__(
            self,
            "top_level_epoch",
            _positive_int(self.top_level_epoch, field="top_level_epoch"),
        )
        object.__setattr__(self, "maturity", _normalize_maturity(self.maturity))
        object.__setattr__(
            self,
            "evidence_generation",
            _non_negative_int(self.evidence_generation, field="evidence_generation"),
        )

    @classmethod
    def from_native_key(
        cls,
        *,
        native_key: NativePreanalysisKey,
        identity_resolution: InputIdentityResolution | None,
        database_uuid: str,
        database_identity: str,
        function_ea: int,
        decompilation_session_id: DecompilationSessionId | str,
        top_level_epoch: int,
        maturity: object,
        evidence_generation: int,
    ) -> "FunctionExecutionIdentity":
        """Build an identity using the manager's exact native-key authority."""
        if not isinstance(native_key, NativePreanalysisKey):
            raise TypeError("native_key must be a NativePreanalysisKey")
        if identity_resolution is not None and not isinstance(
            identity_resolution, InputIdentityResolution
        ):
            raise TypeError("identity_resolution must be an InputIdentityResolution")
        if identity_resolution is not None and (
            identity_resolution.input_identity != native_key.input_identity
        ):
            raise ValueError("native key disagrees with identity resolution")
        verified = bool(
            identity_resolution is not None
            and identity_resolution.external_evidence_allowed
            and identity_resolution.input_identity == native_key.input_identity
            and native_key.input_identity.startswith("sha256:")
        )
        if verified:
            input_identity = native_key.input_identity
            provenance = identity_resolution.provenance
            if not provenance:
                raise ValueError("verified identity requires provenance")
        else:
            input_identity = local_idb_identity(database_uuid)
            provenance = "current_idb"
        return cls(
            input_identity=input_identity,
            input_identity_provenance=provenance,
            external_evidence_allowed=verified,
            database_uuid=database_uuid,
            database_identity=database_identity,
            function_ea=function_ea,
            function_rva=native_key.function_rva,
            function_fingerprint=native_key.function_fingerprint,
            decompilation_session_id=decompilation_session_id,
            top_level_epoch=top_level_epoch,
            maturity=maturity,
            evidence_generation=evidence_generation,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "input_identity": self.input_identity,
            "input_identity_provenance": self.input_identity_provenance,
            "external_evidence_allowed": self.external_evidence_allowed,
            "database_uuid": self.database_uuid,
            "database_identity": self.database_identity,
            "function_ea": self.function_ea,
            "function_rva": self.function_rva,
            "function_fingerprint": self.function_fingerprint,
            "decompilation_session_id": self.decompilation_session_id,
            "top_level_epoch": self.top_level_epoch,
            "maturity": self.maturity.value,
            "evidence_generation": self.evidence_generation,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class MbaObservationContext:
    """Callback-local, immutable context for one MBA instruction observation."""

    function_identity: FunctionExecutionIdentity
    plugin_identity: PluginIdentity
    instruction_ea: int
    block_serial: int | None = None
    block_ea: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.function_identity, FunctionExecutionIdentity):
            raise TypeError("function_identity must be a FunctionExecutionIdentity")
        if not isinstance(self.plugin_identity, PluginIdentity):
            raise TypeError("plugin_identity must be a PluginIdentity")
        _text(self.plugin_identity.name, field="plugin name")
        _text(self.plugin_identity.origin, field="plugin origin")
        for field_name in ("distribution", "version"):
            value = getattr(self.plugin_identity, field_name)
            if value is not None:
                _text(value, field=f"plugin {field_name}")
        object.__setattr__(
            self,
            "instruction_ea",
            _non_negative_int(self.instruction_ea, field="instruction_ea"),
        )
        if self.block_serial is not None:
            object.__setattr__(
                self,
                "block_serial",
                _non_negative_int(self.block_serial, field="block_serial"),
            )
            if self.block_ea is None:
                raise ValueError("block serial requires a block EA anchor")
        if self.block_ea is not None:
            object.__setattr__(
                self, "block_ea", _non_negative_int(self.block_ea, field="block_ea")
            )

    @property
    def identity(self) -> FunctionExecutionIdentity:
        return self.function_identity

    @property
    def block_identity(self) -> str | None:
        if self.block_serial is None:
            return None
        return f"blk{self.block_serial}@0x{self.block_ea:X}"

    def to_dict(self) -> dict[str, object]:
        return {
            "function_identity": self.function_identity.to_dict(),
            "plugin_identity": {
                "name": self.plugin_identity.name,
                "distribution": self.plugin_identity.distribution,
                "version": self.plugin_identity.version,
                "origin": self.plugin_identity.origin,
            },
            "plugin_name": self.plugin_identity.name,
            "plugin_version": self.plugin_identity.version,
            "instruction_ea": self.instruction_ea,
            "block_serial": self.block_serial,
            "block_ea": self.block_ea,
            "block_identity": self.block_identity,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


__all__ = ["FunctionExecutionIdentity", "MbaObservationContext"]
