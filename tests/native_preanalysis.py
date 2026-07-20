"""Explicit portable native identities shared by identity-focused tests."""

from __future__ import annotations

from d810.core.native_preanalysis_key import NativePreanalysisKey


def make_native_key(
    *,
    input_identity: str = "sha256:test-input-a",
    function_rva: int = 0x1000,
    function_fingerprint: str = "sha256:test-function-a",
    profile_fingerprint: str = "sha256:test-profile-a",
    sdk_fingerprint: str = "hexrays:test-sdk-a",
) -> NativePreanalysisKey:
    return NativePreanalysisKey(
        input_identity=input_identity,
        processor="metapc",
        bitness=64,
        function_rva=function_rva,
        function_fingerprint=function_fingerprint,
        profile_fingerprint=profile_fingerprint,
        sdk_fingerprint=sdk_fingerprint,
    )


__all__ = ["make_native_key"]
