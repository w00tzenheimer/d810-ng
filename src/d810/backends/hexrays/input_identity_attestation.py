"""IDA-backed storage and collection for input-identity attestations."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
import sqlite3
import struct
import uuid

from d810.core.input_identity_attestation import (
    CurrentInputIdentityEvidence,
    InputIdentityAttestation,
)
from d810.core.logging import getLogger
from d810.core.persistence import Netnode
from d810.core.typing import Protocol, runtime_checkable


logger = getLogger("d810.input_identity_attestation")

ATTESTATION_NETNODE_NAME = "$ d810.input_identity_attestation.v1"
ATTESTATION_NETNODE_KEY = "current"
_MAX_ATTESTED_FUNCTIONS = 8


class InputIdentityAttestationMalformed(ValueError):
    """The authoritative IDB-local record exists but cannot be trusted."""


@runtime_checkable
class InputIdentityAttestationStore(Protocol):
    def load(self) -> InputIdentityAttestation | None: ...

    def save(self, attestation: InputIdentityAttestation) -> None: ...


class NetnodeInputIdentityAttestationStore:
    """Authoritative per-IDB attestation stored in one dedicated netnode."""

    def __init__(
        self,
        *,
        node: object | None = None,
        node_name: str = ATTESTATION_NETNODE_NAME,
    ) -> None:
        self._node = Netnode(node_name) if node is None else node

    def load(self) -> InputIdentityAttestation | None:
        try:
            payload = self._node[ATTESTATION_NETNODE_KEY]
        except KeyError:
            return None
        except Exception as error:
            raise InputIdentityAttestationMalformed(
                "authoritative input identity attestation cannot be decoded"
            ) from error
        try:
            if not isinstance(payload, Mapping):
                raise TypeError("attestation payload is not a mapping")
            return InputIdentityAttestation.from_dict(payload)
        except (TypeError, ValueError) as error:
            raise InputIdentityAttestationMalformed(
                "authoritative input identity attestation is malformed"
            ) from error

    def save(self, attestation: InputIdentityAttestation) -> None:
        if not isinstance(attestation, InputIdentityAttestation):
            raise TypeError("attestation store requires InputIdentityAttestation")
        self._node[ATTESTATION_NETNODE_KEY] = attestation.to_dict()


class SqliteInputIdentityAttestationMirror:
    """Non-authoritative local inspection mirror keyed by D810 database UUID."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser()

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS input_identity_attestations (
                database_uuid TEXT PRIMARY KEY NOT NULL,
                attestation_json TEXT NOT NULL
            )
            """
        )
        return conn

    def save(self, attestation: InputIdentityAttestation) -> None:
        if not isinstance(attestation, InputIdentityAttestation):
            raise TypeError("attestation mirror requires InputIdentityAttestation")
        payload = json.dumps(
            attestation.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO input_identity_attestations(database_uuid, attestation_json)
                VALUES (?, ?)
                ON CONFLICT(database_uuid)
                DO UPDATE SET attestation_json=excluded.attestation_json
                """,
                (attestation.database_uuid, payload),
            )

    def load(self, database_uuid: str) -> InputIdentityAttestation | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT attestation_json
                FROM input_identity_attestations
                WHERE database_uuid=?
                """,
                (str(database_uuid),),
            ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(str(row[0]))
            if not isinstance(payload, Mapping):
                raise TypeError("mirror payload is not a mapping")
            return InputIdentityAttestation.from_dict(payload)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise InputIdentityAttestationMalformed(
                "diagnostic input identity attestation mirror is malformed"
            ) from error


def function_fingerprint(
    *,
    function_ea: int,
    imagebase: int,
    ida_bytes: object,
    idautils: object,
) -> str:
    """Hash exact native function items in a portable RVA-prefixed format."""

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


def segment_map_digest(ida_segment: object) -> str:
    """Hash a deterministic summary of the current IDB segment map."""

    quantity = int(ida_segment.get_segm_qty())
    if quantity <= 0:
        raise ValueError("current database has no segments")
    rows: list[tuple[int, int, int, int, int]] = []
    for index in range(quantity):
        segment = ida_segment.getnseg(index)
        if segment is None:
            raise ValueError(f"segment {index} is unavailable")
        start = int(segment.start_ea)
        end = int(segment.end_ea)
        if end <= start:
            raise ValueError(f"segment {index} has invalid range")
        rows.append(
            (
                start,
                end,
                int(getattr(segment, "sel", 0)),
                int(getattr(segment, "perm", 0)),
                int(getattr(segment, "bitness", 0)),
            )
        )
    canonical = json.dumps(
        sorted(rows),
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def collect_current_input_identity_evidence(
    function_ea: int,
    *,
    ida_bytes: object,
    ida_funcs: object,
    ida_idp: object,
    ida_nalt: object,
    ida_segment: object,
    idaapi: object,
    idautils: object,
) -> CurrentInputIdentityEvidence:
    """Read every current-IDB property that must match an attestation."""

    pfn = ida_funcs.get_func(int(function_ea))
    if pfn is None:
        raise ValueError(f"0x{int(function_ea):X} is not inside a function")
    function_start = int(pfn.start_ea)
    imagebase = int(ida_nalt.get_imagebase())
    function_rva = function_start - imagebase
    if function_rva < 0:
        raise ValueError("function start precedes the current image base")
    return CurrentInputIdentityEvidence(
        idb_creation_time=int(idaapi.get_idb_ctime()),
        processor=str(ida_idp.get_idp_name() or ""),
        bitness=int(ida_funcs.get_func_bits(pfn)),
        imagebase=imagebase,
        segment_map_digest=segment_map_digest(ida_segment),
        function_rva=function_rva,
        function_fingerprint=function_fingerprint(
            function_ea=function_start,
            imagebase=imagebase,
            ida_bytes=ida_bytes,
            idautils=idautils,
        ),
    )


def loader_sha256(ida_nalt: object) -> str | None:
    """Return a valid loader SHA, or None when IDA lost that field."""

    try:
        digest = ida_nalt.retrieve_input_file_sha256()
    except Exception:
        return None
    if not isinstance(digest, bytes) or len(digest) != hashlib.sha256().digest_size:
        return None
    return digest.hex()


def input_file_path(ida_nalt: object) -> Path | None:
    """Return the IDA input path only as a locator for a later fresh hash."""

    try:
        raw_path = ida_nalt.get_input_file_path()
    except Exception:
        return None
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None
    return Path(raw_path)


def sha256_file(path: Path) -> tuple[str, int] | None:
    """Stream a regular file; return no result for missing/unreadable paths."""

    try:
        if not path.is_file():
            return None
        hasher = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                hasher.update(chunk)
                size += len(chunk)
        return (hasher.hexdigest(), size)
    except OSError:
        return None


def input_size(ida_nalt: object) -> int:
    try:
        value = int(ida_nalt.retrieve_input_file_size())
    except Exception as error:
        raise ValueError("current database has no valid input size") from error
    if value < 0:
        raise ValueError("current database has no valid input size")
    return value


def make_attestation(
    *,
    current: CurrentInputIdentityEvidence,
    input_sha256: str,
    input_size_bytes: int,
    previous: InputIdentityAttestation | None,
) -> InputIdentityAttestation:
    """Refresh a bounded function inventory only for the same loader identity."""

    reuse_previous = (
        previous is not None
        and previous.input_sha256 == input_sha256.lower()
        and previous.first_mismatch(current) not in {
            "idb_creation_time",
            "processor",
            "bitness",
            "imagebase",
            "segment_map_digest",
        }
    )
    function_fingerprints = {} if not reuse_previous else dict(previous.function_fingerprints)
    function_fingerprints[current.function_rva] = current.function_fingerprint
    selected_items = [(current.function_rva, current.function_fingerprint)]
    selected_items.extend(
        (function_rva, fingerprint)
        for function_rva, fingerprint in sorted(function_fingerprints.items())
        if function_rva != current.function_rva
    )
    selected = tuple(selected_items[:_MAX_ATTESTED_FUNCTIONS])
    return InputIdentityAttestation(
        database_uuid=(
            previous.database_uuid if reuse_previous and previous is not None else str(uuid.uuid4())
        ),
        input_sha256=input_sha256,
        input_size=input_size_bytes,
        idb_creation_time=current.idb_creation_time,
        processor=current.processor,
        bitness=current.bitness,
        imagebase=current.imagebase,
        segment_map_digest=current.segment_map_digest,
        function_fingerprints=selected,
    )


def default_mirror_path() -> Path | None:
    """Use IDA's user directory when live; never infer a project path."""

    try:
        import ida_diskio
    except Exception:
        return None
    try:
        return Path(str(ida_diskio.get_user_idadir())) / "d810" / (
            "input_identity_attestations.sqlite3"
        )
    except Exception:
        return None


__all__ = [
    "ATTESTATION_NETNODE_KEY",
    "ATTESTATION_NETNODE_NAME",
    "InputIdentityAttestationMalformed",
    "InputIdentityAttestationStore",
    "NetnodeInputIdentityAttestationStore",
    "SqliteInputIdentityAttestationMirror",
    "collect_current_input_identity_evidence",
    "default_mirror_path",
    "function_fingerprint",
    "input_file_path",
    "input_size",
    "loader_sha256",
    "make_attestation",
    "segment_map_digest",
    "sha256_file",
]
