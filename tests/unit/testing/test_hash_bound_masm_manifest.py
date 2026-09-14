from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
MASM_ROOT = REPO_ROOT / "samples" / "src" / "masm"
MANIFEST_PATH = MASM_ROOT / "hash_bound_seven_manifest.json"

EXPECTED_FIXTURES = (
    (
        "sub_7FFB0E53C420",
        "0x78C420",
        "0x4296",
        "0x4279",
        "092076b62bf2ffb18d32e07e2ec17b8b7166f09d6aaa3e24bc237c37d2161cb2",
    ),
    (
        "sub_7FFB0DE51120",
        "0xA1120",
        "0x7470",
        "0x745E",
        "7b8ba63d39338634d13ce754e44b2cb75b3fe1c74a458c7ac12c3dd3e6bde5dd",
    ),
    (
        "sub_7FFB0DF992D0",
        "0x1E92D0",
        "0x500D",
        "0x4FD4",
        "b4b8f02832eaff8728ce7e4c493a89fcd8e90f8b4e3d35690de4ee80be390e73",
    ),
    (
        "sub_7FFB0DFD1D70",
        "0x221D70",
        "0x1E6FD",
        "0x1E74C",
        "959f90c564ecfe7ff881accf38a90c8d2f3bd73cb26f7fa49fc1f17fa88f5338",
    ),
    (
        "sub_7FFB0E1E69E0",
        "0x4369E0",
        "0x166",
        "0x15A",
        "0c446160e198d6ecc00c915906e48718f5b123f98a1b00ba2888e6ae77f2e81c",
    ),
    (
        "sub_7FFB0E0A2C90",
        "0x2F2C90",
        "0x95CB",
        "0x95BD",
        "c44e8383c2c39fe4a31d50a21447c861906cb6ad696e6420ca63ca6e30e9dc93",
    ),
    (
        "sub_7FFB0E086BE0",
        "0x2D6BE0",
        "0x8CB0",
        "0x8C97",
        "92ca85f671d4c8c2c8230337a987542f4f3b604787b0728787bbdb1df456b0ff",
    ),
)


def _load_manifest() -> dict[str, object]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_manifest_enumerates_the_exact_seven_hash_bound_fixtures() -> None:
    manifest = _load_manifest()

    assert manifest == {
        "schema": "d810.hash-bound-masm-fixtures.v2",
        "fixtures": [
            {
                "function": function,
                "masm": f"{function}.asm",
                "rva": rva,
                "size": size,
                "linked_text_size": linked_text_size,
                "masm_sha256": masm_sha256,
            }
            for function, rva, size, linked_text_size, masm_sha256 in EXPECTED_FIXTURES
        ],
    }


@pytest.mark.parametrize(
    ("function", "rva", "size", "linked_text_size", "masm_sha256"),
    EXPECTED_FIXTURES,
)
def test_fixture_bytes_and_public_symbol_match_the_attested_identity(
    function: str,
    rva: str,
    size: str,
    linked_text_size: str,
    masm_sha256: str,
) -> None:
    del rva, size, linked_text_size
    fixture_path = MASM_ROOT / f"{function}.asm"
    payload = fixture_path.read_bytes()

    assert hashlib.sha256(payload).hexdigest() == masm_sha256
    text = payload.decode("ascii")
    public_pattern = re.compile(rf"(?m)^PUBLIC\s+{re.escape(function)}\s*$")
    assert len(public_pattern.findall(text)) == 1
