from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from d810.testing.hash_bound_build_receipt import (
    generate_hash_bound_build_receipt,
    load_verified_hash_bound_build_receipt,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
LINKED_IMAGE = REPO_ROOT / "samples" / "bins" / "libobfuscated.dll"
FUNCTION = "sub_7FFB0E1E69E0"
FUNCTION_EXTENT = 0x15A


def _write_source_manifest(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": "d810.hash-bound-masm-fixtures.v4",
                "fixtures": [
                    {
                        "function": FUNCTION,
                        "masm": f"{FUNCTION}.asm",
                        "rva": "0x4369E0",
                        "size": "0x166",
                        "linked_text_size": f"0x{FUNCTION_EXTENT:X}",
                        "masm_sha256": "1" * 64,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_generator_resolves_export_and_hashes_exact_linked_extent(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "manifest.json"
    _write_source_manifest(manifest_path)

    receipt = generate_hash_bound_build_receipt(
        manifest_path=manifest_path,
        linked_image_path=LINKED_IMAGE,
    )

    assert receipt["schema"] == "d810.hash-bound-build-receipt.v1"
    assert len(receipt["linked_dll_sha256"]) == 64
    assert receipt["fixtures"] == [
        {
            "function": FUNCTION,
            "entry_rva": "0xA6EA0",
            "extent": "0x15A",
            "linked_sha256": (
                "6fc3e85f546b8c458637ae52a7f4c8fa81dfa3dc801a81c444b0910d94955f06"
            ),
        }
    ]


def test_verifier_rejects_stale_linked_image_with_regeneration_instruction(
    tmp_path: Path,
) -> None:
    manifest_path = tmp_path / "manifest.json"
    receipt_path = tmp_path / "receipt.json"
    stale_image = tmp_path / "libobfuscated.dll"
    _write_source_manifest(manifest_path)
    receipt = generate_hash_bound_build_receipt(
        manifest_path=manifest_path,
        linked_image_path=LINKED_IMAGE,
    )
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    payload = bytearray(LINKED_IMAGE.read_bytes())
    payload[-1] ^= 1
    stale_image.write_bytes(payload)

    with pytest.raises(ValueError, match="regenerate fixture receipt"):
        load_verified_hash_bound_build_receipt(
            receipt_path=receipt_path,
            manifest_path=manifest_path,
            linked_image_path=stale_image,
        )


def test_regeneration_cli_writes_the_verified_receipt(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    receipt_path = tmp_path / "receipt.json"
    _write_source_manifest(manifest_path)
    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "tools/scripts/update_hash_bound_build_receipt.py"),
            "--manifest",
            str(manifest_path),
            "--image",
            str(LINKED_IMAGE),
            "--output",
            str(receipt_path),
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")},
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert receipt_path.is_file()
    load_verified_hash_bound_build_receipt(
        receipt_path=receipt_path,
        manifest_path=manifest_path,
        linked_image_path=LINKED_IMAGE,
    )
