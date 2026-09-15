"""Exact-byte build receipts for relink-stable hash-bound fixtures."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

from d810.core.typing import Any


RECEIPT_SCHEMA = "d810.hash-bound-build-receipt.v1"
MANIFEST_SCHEMA = "d810.hash-bound-masm-fixtures.v4"
REGENERATION_HINT = (
    "regenerate fixture receipt with: PYTHONPATH=src python "
    "tools/scripts/update_hash_bound_build_receipt.py"
)


def _fail_stale(detail: str) -> ValueError:
    return ValueError(f"stale hash-bound build receipt ({detail}); {REGENERATION_HINT}")


def _parse_int(value: object, *, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"{field} must be an integer or base-prefixed string")


def _pe_sections(image: bytes) -> tuple[tuple[int, int, int, int], ...]:
    if len(image) < 0x40 or image[:2] != b"MZ":
        raise ValueError("linked image is not a PE file")
    pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
    if image[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("linked image has no PE signature")
    section_count = struct.unpack_from("<H", image, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", image, pe_offset + 20)[0]
    section_table = pe_offset + 24 + optional_size
    sections: list[tuple[int, int, int, int]] = []
    for index in range(section_count):
        offset = section_table + 40 * index
        virtual_size, virtual_rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", image, offset + 8
        )
        sections.append((virtual_rva, virtual_size, raw_offset, raw_size))
    return tuple(sections)


def _rva_slice(image: bytes, rva: int, size: int) -> bytes:
    if rva < 0 or size < 0:
        raise ValueError("negative PE RVA or extent")
    for virtual_rva, virtual_size, raw_offset, raw_size in _pe_sections(image):
        span = max(virtual_size, raw_size)
        if virtual_rva <= rva and rva + size <= virtual_rva + span:
            start = raw_offset + (rva - virtual_rva)
            end = start + size
            if end > raw_offset + raw_size or end > len(image):
                raise ValueError(f"RVA range 0x{rva:X}+0x{size:X} is not file-backed")
            return image[start:end]
    raise ValueError(f"RVA range 0x{rva:X}+0x{size:X} is not file-backed")


def _read_c_string(image: bytes, rva: int) -> str:
    payload = _rva_slice(image, rva, 1)
    del payload
    for virtual_rva, virtual_size, raw_offset, raw_size in _pe_sections(image):
        if virtual_rva <= rva < virtual_rva + max(virtual_size, raw_size):
            start = raw_offset + (rva - virtual_rva)
            end = image.find(b"\0", start, raw_offset + raw_size)
            if end < 0:
                raise ValueError(f"unterminated PE string at RVA 0x{rva:X}")
            return image[start:end].decode("ascii")
    raise ValueError(f"PE string RVA 0x{rva:X} is not file-backed")


def pe_export_rvas(image: bytes) -> dict[str, int]:
    """Return named, non-forwarded PE exports keyed by exact symbol name."""

    pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
    optional_offset = pe_offset + 24
    magic = struct.unpack_from("<H", image, optional_offset)[0]
    data_directory_offset = optional_offset + (112 if magic == 0x20B else 96)
    if magic not in {0x10B, 0x20B}:
        raise ValueError(f"unsupported PE optional-header magic 0x{magic:X}")
    export_rva, export_size = struct.unpack_from("<II", image, data_directory_offset)
    if export_rva == 0 or export_size == 0:
        return {}
    directory = _rva_slice(image, export_rva, 40)
    (
        _characteristics,
        _timestamp,
        _major,
        _minor,
        _name_rva,
        _base,
        function_count,
        name_count,
        functions_rva,
        names_rva,
        ordinals_rva,
    ) = struct.unpack("<IIHHIIIIIII", directory)
    functions = struct.unpack(
        f"<{function_count}I", _rva_slice(image, functions_rva, 4 * function_count)
    )
    names = struct.unpack(f"<{name_count}I", _rva_slice(image, names_rva, 4 * name_count))
    ordinals = struct.unpack(
        f"<{name_count}H", _rva_slice(image, ordinals_rva, 2 * name_count)
    )
    exports: dict[str, int] = {}
    for name_rva, ordinal in zip(names, ordinals, strict=True):
        if ordinal >= len(functions):
            raise ValueError("PE export ordinal exceeds function table")
        function_rva = int(functions[ordinal])
        if export_rva <= function_rva < export_rva + export_size:
            continue
        exports[_read_c_string(image, int(name_rva))] = function_rva
    return exports


def generate_hash_bound_build_receipt(
    *, manifest_path: Path, linked_image_path: Path
) -> dict[str, Any]:
    manifest_path = Path(manifest_path)
    linked_image_path = Path(linked_image_path)
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise ValueError("unsupported hash-bound source manifest schema")
    image = linked_image_path.read_bytes()
    exports = pe_export_rvas(image)
    fixtures: list[dict[str, str]] = []
    for raw_fixture in manifest.get("fixtures", ()):
        function = str(raw_fixture["function"])
        if function not in exports:
            raise ValueError(f"linked image is missing export {function}")
        extent = _parse_int(
            raw_fixture["linked_text_size"], field=f"{function}.linked_text_size"
        )
        entry_rva = exports[function]
        linked_bytes = _rva_slice(image, entry_rva, extent)
        fixtures.append(
            {
                "function": function,
                "entry_rva": f"0x{entry_rva:X}",
                "extent": f"0x{extent:X}",
                "linked_sha256": hashlib.sha256(linked_bytes).hexdigest(),
            }
        )
    return {
        "schema": RECEIPT_SCHEMA,
        "source_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "linked_dll_sha256": hashlib.sha256(image).hexdigest(),
        "fixtures": fixtures,
    }


def load_verified_hash_bound_build_receipt(
    *, receipt_path: Path, manifest_path: Path, linked_image_path: Path
) -> dict[str, Any]:
    receipt_path = Path(receipt_path)
    manifest_path = Path(manifest_path)
    linked_image_path = Path(linked_image_path)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if receipt.get("schema") != RECEIPT_SCHEMA:
        raise _fail_stale("unsupported schema")
    generated = generate_hash_bound_build_receipt(
        manifest_path=manifest_path,
        linked_image_path=linked_image_path,
    )
    if receipt != generated:
        raise _fail_stale("recorded identities do not match the linked image")
    return receipt


def write_hash_bound_build_receipt(
    *, manifest_path: Path, linked_image_path: Path, receipt_path: Path
) -> None:
    receipt = generate_hash_bound_build_receipt(
        manifest_path=manifest_path,
        linked_image_path=linked_image_path,
    )
    Path(receipt_path).write_text(
        json.dumps(receipt, indent=2) + "\n",
        encoding="utf-8",
    )
