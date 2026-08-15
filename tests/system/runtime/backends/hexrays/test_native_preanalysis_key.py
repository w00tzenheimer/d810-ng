from __future__ import annotations

import hashlib
import json
import struct
import sys
from types import SimpleNamespace

import pytest

from d810.backends.hexrays.native_preanalysis_key import (
    build_native_preanalysis_key,
    fingerprint_profile_config,
    native_toolchain_fingerprint,
    resolve_native_preanalysis_identity,
)


def _install_fake_ida(monkeypatch: pytest.MonkeyPatch) -> None:
    item_bytes = {
        0x401000: b"\x90\x90",
        0x401002: b"\xc3",
    }
    modules = {
        "ida_nalt": SimpleNamespace(
            retrieve_input_file_sha256=lambda: bytes.fromhex("11" * 32),
            retrieve_input_file_size=lambda: 3,
            get_imagebase=lambda: 0x400000,
            get_input_file_path=lambda: "",
        ),
        "ida_funcs": SimpleNamespace(
            get_func=lambda _ea: SimpleNamespace(start_ea=0x401000),
            get_func_bits=lambda _pfn: 64,
        ),
        "idautils": SimpleNamespace(FuncItems=lambda _ea: (0x401002, 0x401000)),
        "ida_bytes": SimpleNamespace(
            get_item_size=lambda ea: len(item_bytes[ea]),
            get_bytes=lambda ea, _size: item_bytes[ea],
        ),
        "ida_idp": SimpleNamespace(get_idp_name=lambda: "PC"),
        "idaapi": SimpleNamespace(
            IDA_SDK_VERSION=930, get_idb_ctime=lambda: 1700000000
        ),
        "ida_hexrays": SimpleNamespace(get_hexrays_version=lambda: "9.3.0.250604"),
        "ida_segment": SimpleNamespace(
            get_segm_qty=lambda: 1,
            getnseg=lambda _index: SimpleNamespace(
                start_ea=0x400000,
                end_ea=0x500000,
                sel=1,
                perm=5,
                bitness=2,
            ),
        ),
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)


def test_build_key_uses_real_loader_function_profile_and_sdk_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_ida(monkeypatch)
    monkeypatch.setattr(
        "d810.backends.hexrays.native_preanalysis_key.NetnodeLocalDatabaseIdentityStore",
        lambda: SimpleNamespace(
            load_or_create=lambda: "60d2b1e4-0c0b-4cc5-9182-41d761e10013"
        ),
    )
    profile = {"project_name": "rhad", "rules": ["unflattening", "dce"]}
    function_hasher = hashlib.sha256()
    for ea, body in ((0x401000, b"\x90\x90"), (0x401002, b"\xc3")):
        function_hasher.update(struct.pack(">QI", ea - 0x400000, len(body)))
        function_hasher.update(body)

    key = build_native_preanalysis_key(0x401000, profile_config=profile)

    assert key.input_identity == f"sha256:{'11' * 32}"
    assert key.processor == "PC"
    assert key.bitness == 64
    assert key.function_rva == 0x1000
    assert key.function_fingerprint == f"sha256:{function_hasher.hexdigest()}"
    assert key.profile_fingerprint == fingerprint_profile_config(profile)
    assert key.sdk_fingerprint == (
        "ida-sdk:930:hexrays:9.3.0.250604:processor:PC:bitness:64:d810:1.0.0b1"
    )


def test_profile_fingerprint_is_canonical() -> None:
    left = {"z": [2, 1], "a": {"enabled": True}}
    right = {"a": {"enabled": True}, "z": [2, 1]}
    expected = hashlib.sha256(
        json.dumps(
            left,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()

    assert fingerprint_profile_config(left) == f"sha256:{expected}"
    assert fingerprint_profile_config(right) == f"sha256:{expected}"


def test_toolchain_fingerprint_segregates_d810_versions() -> None:
    common = {
        "ida_sdk_version": 940,
        "hexrays_version": "9.4.0",
        "processor": "metapc",
        "bitness": 64,
    }

    assert native_toolchain_fingerprint(
        **common, d810_version="1.0.0b1"
    ) != native_toolchain_fingerprint(**common, d810_version="1.0.0b2")


def test_profile_fingerprint_rejects_non_json_values() -> None:
    with pytest.raises(TypeError, match="JSON-serializable"):
        fingerprint_profile_config({"bad": object()})


def test_missing_loader_hash_uses_idb_local_identity_for_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_ida(monkeypatch)
    monkeypatch.setattr(
        sys.modules["ida_nalt"],
        "retrieve_input_file_sha256",
        lambda: b"",
    )

    resolved = resolve_native_preanalysis_identity(
        0x401000,
        profile_config={"profile": "x"},
        local_identity_store=SimpleNamespace(
            load_or_create=lambda: "60d2b1e4-0c0b-4cc5-9182-41d761e10013"
        ),
    )

    assert resolved.native_key is not None
    assert resolved.native_key.input_identity == (
        "idb-local:60d2b1e4-0c0b-4cc5-9182-41d761e10013"
    )
    assert resolved.external_evidence_allowed is False


def test_build_key_fails_closed_without_function(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_ida(monkeypatch)
    monkeypatch.setattr(sys.modules["ida_funcs"], "get_func", lambda _ea: None)

    with pytest.raises(ValueError, match="function"):
        build_native_preanalysis_key(0x401000, profile_config={"profile": "x"})
