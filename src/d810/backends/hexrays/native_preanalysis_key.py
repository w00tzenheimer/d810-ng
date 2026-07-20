"""Acquire a portable native-analysis key from the current IDA database."""

from __future__ import annotations

import hashlib
import json
import struct
from collections.abc import Mapping

from d810.core.native_preanalysis_key import NativePreanalysisKey


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


def _input_identity(ida_nalt: object) -> str:
    digest = ida_nalt.retrieve_input_file_sha256()
    if not isinstance(digest, bytes) or len(digest) != hashlib.sha256().digest_size:
        raise ValueError("current database has no valid input SHA-256")
    return f"sha256:{digest.hex()}"


def _function_fingerprint(
    *,
    function_ea: int,
    imagebase: int,
    ida_bytes: object,
    idautils: object,
) -> str:
    hasher = hashlib.sha256()
    item_eas = tuple(sorted({int(ea) for ea in idautils.FuncItems(function_ea)}))
    if not item_eas:
        raise ValueError(f"function 0x{function_ea:X} has no native items")
    for item_ea in item_eas:
        size = int(ida_bytes.get_item_size(item_ea))
        if size <= 0:
            raise ValueError(f"function item 0x{item_ea:X} has invalid size")
        body = ida_bytes.get_bytes(item_ea, size)
        if not isinstance(body, bytes) or len(body) != size:
            raise ValueError(f"function item 0x{item_ea:X} bytes are unavailable")
        item_rva = item_ea - imagebase
        if item_rva < 0:
            raise ValueError(f"function item 0x{item_ea:X} precedes image base")
        hasher.update(struct.pack(">QI", item_rva, size))
        hasher.update(body)
    return f"sha256:{hasher.hexdigest()}"


def build_native_preanalysis_key(
    function_ea: int,
    *,
    profile_config: Mapping[str, object],
) -> NativePreanalysisKey:
    """Derive every identity component from live loader and profile state.

    Missing loader metadata or unreadable function bytes are fatal.  This
    function never substitutes a process-local path, block serial, or
    ``unknown`` sentinel for a durable identity.
    """
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_idp
    import ida_nalt
    import idaapi
    import idautils

    function_ea = int(function_ea)
    pfn = ida_funcs.get_func(function_ea)
    if pfn is None:
        raise ValueError(f"0x{function_ea:X} is not inside a function")
    function_start = int(pfn.start_ea)
    imagebase = int(ida_nalt.get_imagebase())
    function_rva = function_start - imagebase
    if function_rva < 0:
        raise ValueError("function start precedes the current image base")

    return NativePreanalysisKey(
        input_identity=_input_identity(ida_nalt),
        processor=str(ida_idp.get_idp_name() or ""),
        bitness=int(ida_funcs.get_func_bits(pfn)),
        function_rva=function_rva,
        function_fingerprint=_function_fingerprint(
            function_ea=function_start,
            imagebase=imagebase,
            ida_bytes=ida_bytes,
            idautils=idautils,
        ),
        profile_fingerprint=fingerprint_profile_config(profile_config),
        sdk_fingerprint=(
            f"ida-sdk:{int(idaapi.IDA_SDK_VERSION)}:"
            f"hexrays:{ida_hexrays.get_hexrays_version()}"
        ),
    )


__all__ = ["build_native_preanalysis_key", "fingerprint_profile_config"]
