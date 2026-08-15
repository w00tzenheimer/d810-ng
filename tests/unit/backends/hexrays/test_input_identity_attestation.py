from __future__ import annotations

from pathlib import Path
import sys
from types import SimpleNamespace
import uuid

import pytest

from d810.core.input_identity_attestation import (
    InputIdentityAttestation,
    InputIdentityRecoveryStatus,
)


class _MemoryStore:
    def __init__(
        self,
        attestation: InputIdentityAttestation | None = None,
        *,
        malformed: bool = False,
    ) -> None:
        self.attestation = attestation
        self.malformed = malformed

    def load(self) -> InputIdentityAttestation | None:
        if self.malformed:
            from d810.backends.hexrays.input_identity_attestation import (
                InputIdentityAttestationMalformed,
            )

            raise InputIdentityAttestationMalformed("bad payload")
        return self.attestation

    def save(self, attestation: InputIdentityAttestation) -> None:
        self.attestation = attestation


class _MemoryLocalIdentityStore:
    def __init__(self) -> None:
        self.identity: str | None = None

    def load_or_create(self) -> str:
        if self.identity is None:
            self.identity = "0a2c1f58-08e8-4c93-8c5c-e66a5d2cfc25"
        return self.identity


def _install_fake_ida(
    monkeypatch: pytest.MonkeyPatch,
    *,
    loader_sha256: bytes | None,
    input_path: Path | None = None,
    imagebase: int = 0x400000,
) -> None:
    item_bytes = {0x401000: b"\x90\x90", 0x401002: b"\xc3"}
    segments = (
        SimpleNamespace(start_ea=imagebase, end_ea=imagebase + 0x1000, sel=1, perm=5),
        SimpleNamespace(
            start_ea=imagebase + 0x2000,
            end_ea=imagebase + 0x3000,
            sel=2,
            perm=6,
        ),
    )
    modules = {
        "ida_nalt": SimpleNamespace(
            retrieve_input_file_sha256=lambda: loader_sha256,
            retrieve_input_file_size=lambda: 8192,
            get_imagebase=lambda: imagebase,
            get_input_file_path=lambda: "" if input_path is None else str(input_path),
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
        "idaapi": SimpleNamespace(IDA_SDK_VERSION=930, get_idb_ctime=lambda: 1700000000),
        "ida_hexrays": SimpleNamespace(get_hexrays_version=lambda: "9.3.0.250604"),
        "ida_segment": SimpleNamespace(
            get_segm_qty=lambda: len(segments),
            getnseg=segments.__getitem__,
        ),
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)


def test_loader_sha_capture_writes_authoritative_store_and_sqlite_mirror(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from d810.backends.hexrays.input_identity_attestation import (
        SqliteInputIdentityAttestationMirror,
    )
    from d810.backends.hexrays.native_preanalysis_key import (
        resolve_native_preanalysis_identity,
    )

    _install_fake_ida(monkeypatch, loader_sha256=bytes.fromhex("11" * 32))
    store = _MemoryStore()
    local_store = _MemoryLocalIdentityStore()
    mirror_path = tmp_path / "identity.sqlite3"

    resolved = resolve_native_preanalysis_identity(
        0x401000,
        profile_config={"profile": "x"},
        attestation_store=store,
        local_identity_store=local_store,
        mirror_path=mirror_path,
    )

    assert resolved.native_key is not None
    assert resolved.identity_resolution.status is InputIdentityRecoveryStatus.LOADER_SHA_CAPTURED
    assert store.attestation is not None
    assert store.attestation.input_sha256 == "11" * 32
    assert store.attestation.function_fingerprints[0][0] == 0x1000
    assert resolved.identity_resolution.database_uuid == local_store.load_or_create()
    assert store.attestation.database_uuid == local_store.load_or_create()
    assert SqliteInputIdentityAttestationMirror(mirror_path).load(
        store.attestation.database_uuid
    ) == store.attestation


def test_missing_loader_sha_uses_current_idb_identity_for_local_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from d810.backends.hexrays.native_preanalysis_key import (
        resolve_native_preanalysis_identity,
    )

    _install_fake_ida(monkeypatch, loader_sha256=None)

    local_store = _MemoryLocalIdentityStore()
    resolved = resolve_native_preanalysis_identity(
        0x401000,
        profile_config={"profile": "x"},
        attestation_store=_MemoryStore(),
        local_identity_store=local_store,
        mirror_path=tmp_path / "identity.sqlite3",
    )

    assert resolved.native_key is not None
    assert resolved.native_key.input_identity == "idb-local:" + local_store.load_or_create()
    assert resolved.identity_resolution.status is InputIdentityRecoveryStatus.IDB_LOCAL
    assert resolved.external_evidence_allowed is False
    assert resolved.identity_resolution.database_uuid == local_store.load_or_create()


def test_local_database_identity_store_persists_a_canonical_uuid() -> None:
    from d810.backends.hexrays.input_identity_attestation import (
        NetnodeLocalDatabaseIdentityStore,
    )

    node: dict[str, object] = {}
    first = NetnodeLocalDatabaseIdentityStore(node=node).load_or_create()

    assert str(uuid.UUID(first)) == first
    assert NetnodeLocalDatabaseIdentityStore(node=node).load_or_create() == first


def test_missing_loader_sha_ignores_stale_or_malformed_attestation_for_local_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from d810.backends.hexrays.native_preanalysis_key import (
        resolve_native_preanalysis_identity,
    )

    _install_fake_ida(monkeypatch, loader_sha256=None)

    local_store = _MemoryLocalIdentityStore()
    resolved = resolve_native_preanalysis_identity(
        0x401000,
        profile_config={"profile": "x"},
        attestation_store=_MemoryStore(malformed=True),
        local_identity_store=local_store,
        mirror_path=tmp_path / "identity.sqlite3",
    )

    assert resolved.native_key is not None
    assert resolved.native_key.input_identity == "idb-local:" + local_store.load_or_create()
    assert resolved.identity_resolution.status is InputIdentityRecoveryStatus.IDB_LOCAL
    assert resolved.external_evidence_allowed is False
