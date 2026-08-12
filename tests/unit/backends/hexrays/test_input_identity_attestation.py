from __future__ import annotations

import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace

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
    mirror_path = tmp_path / "identity.sqlite3"

    resolved = resolve_native_preanalysis_identity(
        0x401000,
        profile_config={"profile": "x"},
        allow_attested_recovery=False,
        attestation_store=store,
        mirror_path=mirror_path,
    )

    assert resolved.native_key is not None
    assert resolved.identity_resolution.status is InputIdentityRecoveryStatus.LOADER_SHA_CAPTURED
    assert store.attestation is not None
    assert store.attestation.input_sha256 == "11" * 32
    assert store.attestation.function_fingerprints[0][0] == 0x1000
    assert (
        resolved.identity_resolution.database_uuid == store.attestation.database_uuid
    )
    assert SqliteInputIdentityAttestationMirror(mirror_path).load(
        store.attestation.database_uuid
    ) == store.attestation


def test_matching_attestation_recovers_local_only_when_input_is_absent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from d810.backends.hexrays.native_preanalysis_key import (
        resolve_native_preanalysis_identity,
    )

    _install_fake_ida(monkeypatch, loader_sha256=None)
    initial_store = _MemoryStore()
    _install_fake_ida(monkeypatch, loader_sha256=bytes.fromhex("11" * 32))
    resolve_native_preanalysis_identity(
        0x401000,
        profile_config={"profile": "x"},
        allow_attested_recovery=False,
        attestation_store=initial_store,
        mirror_path=tmp_path / "first.sqlite3",
    )
    _install_fake_ida(monkeypatch, loader_sha256=None)

    resolved = resolve_native_preanalysis_identity(
        0x401000,
        profile_config={"profile": "x"},
        allow_attested_recovery=True,
        attestation_store=initial_store,
        mirror_path=tmp_path / "second.sqlite3",
    )

    assert resolved.native_key is not None
    assert resolved.native_key.input_identity == "sha256:" + ("11" * 32)
    assert (
        resolved.identity_resolution.status
        is InputIdentityRecoveryStatus.RECOVERED_LOCAL_ONLY
    )
    assert resolved.external_evidence_allowed is False


def test_matching_input_file_hash_enables_external_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from d810.backends.hexrays.native_preanalysis_key import (
        resolve_native_preanalysis_identity,
    )

    binary = tmp_path / "candidate.bin"
    binary.write_bytes(b"attested input")
    digest = hashlib.sha256(binary.read_bytes()).digest()
    store = _MemoryStore()
    _install_fake_ida(monkeypatch, loader_sha256=digest, input_path=binary)
    resolve_native_preanalysis_identity(
        0x401000,
        profile_config={"profile": "x"},
        allow_attested_recovery=False,
        attestation_store=store,
        mirror_path=tmp_path / "capture.sqlite3",
    )
    _install_fake_ida(monkeypatch, loader_sha256=None, input_path=binary)

    resolved = resolve_native_preanalysis_identity(
        0x401000,
        profile_config={"profile": "x"},
        allow_attested_recovery=True,
        attestation_store=store,
        mirror_path=tmp_path / "recover.sqlite3",
    )

    assert resolved.native_key is not None
    assert (
        resolved.identity_resolution.status
        is InputIdentityRecoveryStatus.RECOVERED_FILE_HASH_VERIFIED
    )
    assert resolved.external_evidence_allowed is True


def test_mirror_never_recovers_when_authoritative_store_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from d810.backends.hexrays.input_identity_attestation import (
        SqliteInputIdentityAttestationMirror,
    )
    from d810.backends.hexrays.native_preanalysis_key import (
        resolve_native_preanalysis_identity,
    )

    capture_store = _MemoryStore()
    _install_fake_ida(monkeypatch, loader_sha256=bytes.fromhex("11" * 32))
    captured = resolve_native_preanalysis_identity(
        0x401000,
        profile_config={"profile": "x"},
        allow_attested_recovery=False,
        attestation_store=capture_store,
        mirror_path=tmp_path / "capture.sqlite3",
    )
    assert capture_store.attestation is not None
    mirror_path = tmp_path / "mirror.sqlite3"
    SqliteInputIdentityAttestationMirror(mirror_path).save(capture_store.attestation)
    _install_fake_ida(monkeypatch, loader_sha256=None)

    recovered = resolve_native_preanalysis_identity(
        0x401000,
        profile_config={"profile": "x"},
        allow_attested_recovery=True,
        attestation_store=_MemoryStore(),
        mirror_path=mirror_path,
    )

    assert captured.native_key is not None
    assert recovered.native_key is None
    assert (
        recovered.identity_resolution.status
        is InputIdentityRecoveryStatus.ATTESTATION_MISSING
    )


def test_malformed_authoritative_store_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from d810.backends.hexrays.native_preanalysis_key import (
        resolve_native_preanalysis_identity,
    )

    _install_fake_ida(monkeypatch, loader_sha256=None)
    recovered = resolve_native_preanalysis_identity(
        0x401000,
        profile_config={"profile": "x"},
        allow_attested_recovery=True,
        attestation_store=_MemoryStore(malformed=True),
        mirror_path=tmp_path / "mirror.sqlite3",
    )

    assert recovered.native_key is None
    assert (
        recovered.identity_resolution.status
        is InputIdentityRecoveryStatus.ATTESTATION_MALFORMED
    )


def test_present_input_with_different_hash_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from d810.backends.hexrays.native_preanalysis_key import (
        resolve_native_preanalysis_identity,
    )

    captured_file = tmp_path / "candidate.bin"
    captured_file.write_bytes(b"initial")
    store = _MemoryStore()
    _install_fake_ida(
        monkeypatch,
        loader_sha256=hashlib.sha256(captured_file.read_bytes()).digest(),
        input_path=captured_file,
    )
    resolve_native_preanalysis_identity(
        0x401000,
        profile_config={"profile": "x"},
        allow_attested_recovery=False,
        attestation_store=store,
        mirror_path=tmp_path / "capture.sqlite3",
    )
    captured_file.write_bytes(b"replacement")
    _install_fake_ida(monkeypatch, loader_sha256=None, input_path=captured_file)

    recovered = resolve_native_preanalysis_identity(
        0x401000,
        profile_config={"profile": "x"},
        allow_attested_recovery=True,
        attestation_store=store,
        mirror_path=tmp_path / "recover.sqlite3",
    )

    assert recovered.native_key is None
    assert (
        recovered.identity_resolution.status
        is InputIdentityRecoveryStatus.INPUT_FILE_HASH_MISMATCH
    )
