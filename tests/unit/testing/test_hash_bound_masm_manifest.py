from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path

import pytest

from tests.system.cases.libobfuscated_comprehensive import DAC_MASM_CASES
from tests.system.e2e.hash_bound_fixture_receipts import HASH_BOUND_LINKED_EXTENTS


REPO_ROOT = Path(__file__).resolve().parents[3]
MASM_ROOT = REPO_ROOT / "samples" / "src" / "masm"
MANIFEST_PATH = MASM_ROOT / "hash_bound_seven_manifest.json"
PROFILE_PATH = (
    REPO_ROOT / "src" / "d810" / "conf" / "hash_bound_v4_user_cfg_const_simplify_solve.json"
)
PROFILE_SHA256 = "1c9dd1d14158e2be7e9a838577f79c201e7eed72cd01c5911100068f098f1c12"
LINKED_DLL_PATH = REPO_ROOT / "samples" / "bins" / "libobfuscated.dll"

EXPECTED_FIXTURES = (
    (
        "sub_7FFB0E53C420",
        "0x78C420",
        "0x4296",
        "0x9C260",
        "0x4279",
        "e9304cfca6b973d63acdc6c0d84106b774628c5bd376612f5517a5464825e9f2",
        "092076b62bf2ffb18d32e07e2ec17b8b7166f09d6aaa3e24bc237c37d2161cb2",
    ),
    (
        "sub_7FFB0DE51120",
        "0xA1120",
        "0x7470",
        "0x58A40",
        "0x745E",
        "1710009f3ac9083b76558226cecbfb31e9be1920f2fa0d98016f62e8d380b778",
        "7b8ba63d39338634d13ce754e44b2cb75b3fe1c74a458c7ac12c3dd3e6bde5dd",
    ),
    (
        "sub_7FFB0DF992D0",
        "0x1E92D0",
        "0x500D",
        "0x630B4",
        "0x4FE9",
        "7e940fd8eca74f61333a547e3e5cb7834d34ed08bbbf1b8d0071c326d7103c8e",
        "040dfbbcad55230b358dded437de33418bd9d1f8132c268559adf80751d713c5",
    ),
    (
        "sub_7FFB0DFD1D70",
        "0x221D70",
        "0x1E6FD",
        "0x680A0",
        "0x1E74C",
        "4ad6639c98385f8970066505c925992da07c9565776b356daa5c63e1a0bddea1",
        "959f90c564ecfe7ff881accf38a90c8d2f3bd73cb26f7fa49fc1f17fa88f5338",
    ),
    (
        "sub_7FFB0E1E69E0",
        "0x4369E0",
        "0x166",
        "0x98D80",
        "0x15A",
        "c8f2550d44cf2013f5e6c81cd935be45e8158140490a99251c684e0f8d6fba08",
        "0c446160e198d6ecc00c915906e48718f5b123f98a1b00ba2888e6ae77f2e81c",
    ),
    (
        "sub_7FFB0E0A2C90",
        "0x2F2C90",
        "0x95CB",
        "0x8F7B0",
        "0x95BD",
        "efd306d013d8972a6da44dcf6012fc192cfe141d5198329aafab02a5cd93ba3b",
        "f85a24406da37b37ee2c49ee0d4986887210c6242164f2311743068f6ddb5a12",
    ),
    (
        "sub_7FFB0E086BE0",
        "0x2D6BE0",
        "0x8CB0",
        "0x86958",
        "0x8CAB",
        "f53e90da1115110ffb01e6825134eaf572680dfcc60b6b307e4e22cc8593d44f",
        "5a04f8536324963ce70b7cd564630c51b4cd11934de215058f25b0ffc447c964",
    ),
)


def _load_manifest() -> dict[str, object]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _linked_bytes(rva: int, size: int) -> bytes:
    payload = LINKED_DLL_PATH.read_bytes()
    pe_offset = struct.unpack_from("<I", payload, 0x3C)[0]
    assert payload[pe_offset : pe_offset + 4] == b"PE\0\0"
    section_count, optional_size = struct.unpack_from("<H12xH", payload, pe_offset + 6)
    section_offset = pe_offset + 24 + optional_size
    for index in range(section_count):
        header = section_offset + index * 40
        virtual_size, virtual_rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", payload, header + 8
        )
        span = max(virtual_size, raw_size)
        if virtual_rva <= rva and rva + size <= virtual_rva + span:
            start = raw_offset + (rva - virtual_rva)
            return payload[start : start + size]
    raise AssertionError(f"RVA range 0x{rva:X}+0x{size:X} is not file-backed")


def test_manifest_enumerates_the_exact_seven_hash_bound_fixtures() -> None:
    manifest = _load_manifest()

    assert manifest == {
        "schema": "d810.hash-bound-masm-fixtures.v3",
        "native_source": {
            "sha256": "835fe0d11e03b4bb3886b463efc56791db23808c8b80e9cf40193427eff83109",
            "segment_override_repairs": [
                {
                    "function": "sub_7FFB0DF992D0",
                    "exported_masm_sha256": (
                        "b4b8f02832eaff8728ce7e4c493a89fcd8e90f8b4e3d35690de4ee80be390e73"
                    ),
                    "segment": "gs",
                    "operand": "qword ptr [60h]",
                    "count": 21,
                },
                {
                    "function": "sub_7FFB0E086BE0",
                    "exported_masm_sha256": (
                        "92ca85f671d4c8c2c8230337a987542f4f3b604787b0728787bbdb1df456b0ff"
                    ),
                    "segment": "gs",
                    "operand": "qword ptr [60h]",
                    "count": 20,
                },
            ],
        },
        "profile": {
            "name": PROFILE_PATH.name,
            "sha256": PROFILE_SHA256,
        },
        "fixtures": [
            {
                "function": function,
                "masm": f"{function}.asm",
                "rva": rva,
                "size": size,
                "linked_rva": linked_rva,
                "linked_text_size": linked_text_size,
                "linked_sha256": linked_sha256,
                "masm_sha256": masm_sha256,
            }
            for (
                function,
                rva,
                size,
                linked_rva,
                linked_text_size,
                linked_sha256,
                masm_sha256,
            ) in EXPECTED_FIXTURES
        ],
    }


@pytest.mark.parametrize(
    (
        "function",
        "rva",
        "size",
        "linked_rva",
        "linked_text_size",
        "linked_sha256",
        "masm_sha256",
    ),
    EXPECTED_FIXTURES,
)
def test_fixture_bytes_and_public_symbol_match_the_attested_identity(
    function: str,
    rva: str,
    size: str,
    linked_rva: str,
    linked_text_size: str,
    linked_sha256: str,
    masm_sha256: str,
) -> None:
    del rva, size, linked_rva, linked_text_size, linked_sha256
    fixture_path = MASM_ROOT / f"{function}.asm"
    payload = fixture_path.read_bytes()

    assert hashlib.sha256(payload).hexdigest() == masm_sha256
    text = payload.decode("ascii")
    public_pattern = re.compile(rf"(?m)^PUBLIC\s+{re.escape(function)}\s*$")
    assert len(public_pattern.findall(text)) == 1


def test_native_segment_override_repairs_are_present_in_corrected_masm() -> None:
    manifest = _load_manifest()
    repairs = manifest["native_source"]["segment_override_repairs"]

    for repair in repairs:
        text = (MASM_ROOT / f"{repair['function']}.asm").read_text(encoding="ascii")
        bare_operand = str(repair["operand"])
        corrected_operand = f"{repair['segment']}:{bare_operand.removeprefix('qword ptr ')}"
        assert bare_operand not in text.replace(f"qword ptr {corrected_operand}", "")
        assert text.count(f"qword ptr {corrected_operand}") == int(repair["count"])


def test_hash_bound_profile_matches_the_attested_configuration() -> None:
    assert hashlib.sha256(PROFILE_PATH.read_bytes()).hexdigest() == PROFILE_SHA256


@pytest.mark.parametrize(
    (
        "function",
        "rva",
        "size",
        "linked_rva",
        "linked_text_size",
        "linked_sha256",
        "masm_sha256",
    ),
    EXPECTED_FIXTURES,
)
def test_linked_fixture_bytes_match_the_canonical_pe(
    function: str,
    rva: str,
    size: str,
    linked_rva: str,
    linked_text_size: str,
    linked_sha256: str,
    masm_sha256: str,
) -> None:
    del function, rva, size, masm_sha256
    payload = _linked_bytes(int(linked_rva, 0), int(linked_text_size, 0))

    assert len(payload) == int(linked_text_size, 0)
    assert hashlib.sha256(payload).hexdigest() == linked_sha256


def test_all_hash_bound_fixtures_have_strict_native_cases() -> None:
    cases = {
        case.function: case
        for case in DAC_MASM_CASES
        if case.function in HASH_BOUND_LINKED_EXTENTS
    }

    assert set(cases) == set(HASH_BOUND_LINKED_EXTENTS)
    for case in cases.values():
        assert case.project == PROFILE_PATH.name
        assert case.must_change is True
        assert case.deobfuscated_not_contains
