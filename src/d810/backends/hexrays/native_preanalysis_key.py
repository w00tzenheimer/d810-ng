"""Acquire a portable native-analysis key from the current IDA database."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from d810.backends.hexrays.input_identity_attestation import (
    InputIdentityAttestationMalformed,
    InputIdentityAttestationStore,
    NetnodeInputIdentityAttestationStore,
    SqliteInputIdentityAttestationMirror,
    collect_current_input_identity_evidence,
    default_mirror_path,
    input_file_path,
    input_size,
    loader_sha256,
    make_attestation,
    sha256_file,
)
from d810.core.input_identity_attestation import (
    InputIdentityRecoveryStatus,
    InputIdentityResolution,
    resolve_attested_input_identity,
)
from d810.core.logging import getLogger
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.settings import get_settings


logger = getLogger("d810.native_preanalysis_key")


@dataclass(frozen=True, slots=True)
class NativePreanalysisIdentityResolution:
    """A native key together with its loader or attestation provenance."""

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


def _malformed_resolution() -> InputIdentityResolution:
    return InputIdentityResolution(
        status=InputIdentityRecoveryStatus.ATTESTATION_MALFORMED,
        input_identity=None,
        provenance=None,
        external_evidence_allowed=False,
    )


def _refresh_attestation(
    *,
    store: InputIdentityAttestationStore | None,
    mirror_path: Path | None,
    current,
    loader_digest: str,
    ida_nalt: object,
) -> None:
    if store is None:
        return
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
        )
        store.save(attestation)
    except Exception as error:
        logger.warning("Failed to persist input identity attestation: %s", error)
        return
    if mirror_path is None:
        return
    try:
        SqliteInputIdentityAttestationMirror(mirror_path).save(attestation)
    except Exception as error:
        logger.warning("Failed to mirror input identity attestation: %s", error)


def resolve_native_preanalysis_identity(
    function_ea: int,
    *,
    profile_config: Mapping[str, object],
    allow_attested_recovery: bool | None = None,
    attestation_store: InputIdentityAttestationStore | None = None,
    mirror_path: str | Path | None = None,
) -> NativePreanalysisIdentityResolution:
    """Derive a native key without treating input-path text as identity."""

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
    loader_digest = loader_sha256(ida_nalt)
    store = attestation_store if attestation_store is not None else _default_attestation_store()
    resolved_mirror_path = (
        Path(mirror_path)
        if mirror_path is not None
        else default_mirror_path()
    )
    if loader_digest is not None:
        _refresh_attestation(
            store=store,
            mirror_path=resolved_mirror_path,
            current=current,
            loader_digest=loader_digest,
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
    else:
        try:
            attestation = None if store is None else store.load()
        except InputIdentityAttestationMalformed:
            identity_resolution = _malformed_resolution()
        else:
            candidate_path = input_file_path(ida_nalt)
            candidate_hash = (
                None if candidate_path is None else sha256_file(candidate_path)
            )
            identity_resolution = resolve_attested_input_identity(
                loader_sha256=None,
                allow_recovery=(
                    get_settings().allow_attested_input_identity_recovery
                    if allow_attested_recovery is None
                    else bool(allow_attested_recovery)
                ),
                attestation=attestation,
                current=current,
                input_file_exists=candidate_path is not None and candidate_path.is_file(),
                input_file_sha256=(
                    None if candidate_hash is None else candidate_hash[0]
                ),
            )
    if identity_resolution.input_identity is None:
        return NativePreanalysisIdentityResolution(None, identity_resolution)
    native_key = NativePreanalysisKey(
        input_identity=identity_resolution.input_identity,
        processor=current.processor,
        bitness=current.bitness,
        function_rva=current.function_rva,
        function_fingerprint=current.function_fingerprint,
        profile_fingerprint=fingerprint_profile_config(profile_config),
        sdk_fingerprint=(
            f"ida-sdk:{int(idaapi.IDA_SDK_VERSION)}:"
            f"hexrays:{ida_hexrays.get_hexrays_version()}"
        ),
    )
    return NativePreanalysisIdentityResolution(native_key, identity_resolution)


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
        raise ValueError(
            "current database has no valid input SHA-256: "
            + resolution.identity_resolution.reason
        )
    return resolution.native_key


__all__ = [
    "NativePreanalysisIdentityResolution",
    "build_native_preanalysis_key",
    "fingerprint_profile_config",
    "resolve_native_preanalysis_identity",
]
