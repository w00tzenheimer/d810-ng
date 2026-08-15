"""Acquire a portable native-analysis key from the current IDA database."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path

from d810 import __version__ as D810_VERSION
from d810.backends.hexrays.input_identity_attestation import (
    InputIdentityAttestationMalformed,
    InputIdentityAttestationStore,
    LocalDatabaseIdentityStore,
    NetnodeLocalDatabaseIdentityStore,
    NetnodeInputIdentityAttestationStore,
    SqliteInputIdentityAttestationMirror,
    collect_current_input_identity_evidence,
    default_mirror_path,
    input_size,
    loader_sha256,
    make_attestation,
)
from d810.core.input_identity_attestation import (
    InputIdentityAttestation,
    InputIdentityRecoveryStatus,
    InputIdentityResolution,
    local_idb_identity,
    resolve_attested_input_identity,
)
from d810.core.logging import getLogger
from d810.core.native_preanalysis_key import NativePreanalysisKey


logger = getLogger("d810.native_preanalysis_key")


def native_toolchain_fingerprint(
    *,
    ida_sdk_version: int,
    hexrays_version: str,
    processor: str,
    bitness: int,
    d810_version: str = D810_VERSION,
) -> str:
    """Return the exact toolchain boundary for reusable execution history."""

    return (
        f"ida-sdk:{int(ida_sdk_version)}:hexrays:{hexrays_version}:"
        f"processor:{processor}:bitness:{int(bitness)}:d810:{d810_version}"
    )


@dataclass(frozen=True, slots=True)
class NativePreanalysisIdentityResolution:
    """A native key together with loader-SHA or IDB-local provenance."""

    native_key: NativePreanalysisKey | None
    identity_resolution: InputIdentityResolution

    @property
    def external_evidence_allowed(self) -> bool:
        return self.identity_resolution.external_evidence_allowed


def fingerprint_profile_config(profile_config: Mapping[str, object]) -> str:
    """Hash the effective d810 profile without order-dependent JSON output."""
    try:
        encoded = json.dumps(
            profile_config,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise TypeError(
            "native preanalysis profile config must be JSON-serializable"
        ) from error
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _default_attestation_store() -> InputIdentityAttestationStore | None:
    try:
        return NetnodeInputIdentityAttestationStore()
    except Exception as error:
        logger.warning("Input identity attestation netnode is unavailable: %s", error)
        return None


def _refresh_attestation(
    *,
    store: InputIdentityAttestationStore | None,
    mirror_path: Path | None,
    current,
    loader_digest: str,
    database_uuid: str,
    ida_nalt: object,
) -> InputIdentityAttestation | None:
    if store is None:
        return None
    try:
        previous = store.load()
    except InputIdentityAttestationMalformed as error:
        logger.warning("Replacing malformed input identity attestation: %s", error)
        previous = None
    try:
        attestation = make_attestation(
            current=current,
            input_sha256=loader_digest,
            input_size_bytes=input_size(ida_nalt),
            previous=previous,
            database_uuid=database_uuid,
        )
        store.save(attestation)
    except Exception as error:
        logger.warning("Failed to persist input identity attestation: %s", error)
        return None
    if mirror_path is None:
        return attestation
    try:
        SqliteInputIdentityAttestationMirror(mirror_path).save(attestation)
    except Exception as error:
        logger.warning("Failed to mirror input identity attestation: %s", error)
    return attestation


def resolve_native_preanalysis_identity(
    function_ea: int,
    *,
    profile_config: Mapping[str, object],
    attestation_store: InputIdentityAttestationStore | None = None,
    local_identity_store: LocalDatabaseIdentityStore | None = None,
    mirror_path: str | Path | None = None,
) -> NativePreanalysisIdentityResolution:
    """Derive a local mutation key without treating input-path text as identity."""

    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_idp
    import ida_nalt
    import ida_segment
    import idaapi
    import idautils

    current = collect_current_input_identity_evidence(
        int(function_ea),
        ida_bytes=ida_bytes,
        ida_funcs=ida_funcs,
        ida_idp=ida_idp,
        ida_nalt=ida_nalt,
        ida_segment=ida_segment,
        idaapi=idaapi,
        idautils=idautils,
    )
    local_store = (
        local_identity_store
        if local_identity_store is not None
        else NetnodeLocalDatabaseIdentityStore()
    )
    database_uuid = local_store.load_or_create()
    loader_digest = loader_sha256(ida_nalt)
    store = (
        attestation_store
        if attestation_store is not None
        else _default_attestation_store()
    )
    resolved_mirror_path = (
        Path(mirror_path) if mirror_path is not None else default_mirror_path()
    )
    if loader_digest is not None:
        _refresh_attestation(
            store=store,
            mirror_path=resolved_mirror_path,
            current=current,
            loader_digest=loader_digest,
            database_uuid=database_uuid,
            ida_nalt=ida_nalt,
        )
        identity_resolution = resolve_attested_input_identity(
            loader_sha256=loader_digest,
            allow_recovery=False,
            attestation=None,
            current=current,
            input_file_exists=False,
            input_file_sha256=None,
        )
        identity_resolution = replace(
            identity_resolution,
            database_uuid=database_uuid,
        )
    else:
        identity_resolution = InputIdentityResolution(
            status=InputIdentityRecoveryStatus.IDB_LOCAL,
            input_identity=local_idb_identity(local_store.load_or_create()),
            provenance="current_idb",
            external_evidence_allowed=False,
            database_uuid=database_uuid,
        )
    native_key = NativePreanalysisKey(
        input_identity=(
            identity_resolution.input_identity
            if identity_resolution.input_identity is not None
            else _raise_missing_identity()
        ),
        processor=current.processor,
        bitness=current.bitness,
        function_rva=current.function_rva,
        function_fingerprint=current.function_fingerprint,
        profile_fingerprint=fingerprint_profile_config(profile_config),
        sdk_fingerprint=native_toolchain_fingerprint(
            ida_sdk_version=int(idaapi.IDA_SDK_VERSION),
            hexrays_version=str(ida_hexrays.get_hexrays_version()),
            processor=current.processor,
            bitness=current.bitness,
        ),
    )
    return NativePreanalysisIdentityResolution(native_key, identity_resolution)


def _raise_missing_identity() -> str:
    raise ValueError("current database has no valid local identity")


def build_native_preanalysis_key(
    function_ea: int,
    *,
    profile_config: Mapping[str, object],
) -> NativePreanalysisKey:
    """Preserve the legacy key-returning API and its fail-closed behavior."""

    resolution = resolve_native_preanalysis_identity(
        function_ea,
        profile_config=profile_config,
    )
    if resolution.native_key is None:
        raise ValueError("current database has no valid local identity")
    return resolution.native_key


__all__ = [
    "NativePreanalysisIdentityResolution",
    "build_native_preanalysis_key",
    "fingerprint_profile_config",
    "native_toolchain_fingerprint",
    "resolve_native_preanalysis_identity",
]
