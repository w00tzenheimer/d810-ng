"""Check the actual AntiDebug DSL contract without loading IDA test fixtures."""

from pathlib import Path
import runpy

import pytest

from d810.testing.assertions import (
    assert_contains,
    assert_not_contains,
    assert_regex_contains,
)


@pytest.fixture(scope="module")
def antidebug_case():
    namespace = runpy.run_path(str(
        Path(__file__).resolve().parents[2]
        / "system/cases/libobfuscated_comprehensive.py"
    ))
    return next(case for case in namespace["ALL_CASES"]
                if case.function == "AntiDebug_ExceptionFilter")


def _assert_case(case, code):
    assert_contains(code, case.deobfuscated_contains)
    assert_regex_contains(code, case.deobfuscated_regexes)
    assert_not_contains(code, case.deobfuscated_not_contains)


_DWORD_READ = "__ROL4__(*(_DWORD *)(4 - 0x4EFFFFFF8001FF23LL), 0x1D)"
_QWORD_READ = "__ROL8__(MEMORY[0xB10000007FFE03FD] ^ 0x65LL, 0x38)"


@pytest.mark.parametrize("dword_read", [
    _DWORD_READ,
    "__ROL4__(MEMORY[0xB10000007FFE00E1], 0x1D)",
    "__ROL4__(*(_DWORD *)(0xB10000007FFE00E1uLL), 0x1D)",
])
def test_antidebug_contract_accepts_both_distinct_native_reads(antidebug_case, dword_read):
    _assert_case(antidebug_case, f"a = {dword_read}; b = {_QWORD_READ};")


@pytest.mark.parametrize("code", [
    f"a = __ROL4__(MEMORY[0xB10000007FFE03FD], 0x1D); b = {_QWORD_READ};",
    f"b = {_QWORD_READ};",
    f"a = {_DWORD_READ.replace('_DWORD', '_QWORD')}; b = {_QWORD_READ};",
    f"a = __ROL8__(MEMORY[0xB10000007FFE00E1], 0x1D); b = {_QWORD_READ};",
    "a = __ROL4__(MEMORY[0xB10000007FFE00E1], 0x1D);",
    "a = __ROL4__(MEMORY[0xB10000007FFE00E1], 0x1D); "
    "b = __ROL4__(MEMORY[0xB10000007FFE03FD] ^ 0x65LL, 0x18);",
    "switch (state) { case 0: a = __ROL4__(MEMORY[0xB10000007FFE00E1], 0x1D); "
    f"b = {_QWORD_READ}; }}",
])
def test_antidebug_contract_rejects_missing_wrong_or_still_flattened_reads(antidebug_case, code):
    with pytest.raises(AssertionError):
        _assert_case(antidebug_case, code)


def test_antidebug_address_expressions_are_distinct_uint64_offsets():
    mask = (1 << 64) - 1
    base = 0xB10000007FFE00B8 ^ 0x65
    assert ((base + 4) & mask) == 0xB10000007FFE00E1
    assert ((4 - 0x4EFFFFFF8001FF23) & mask) == 0xB10000007FFE00E1
    assert ((base + 0x320) & mask) == 0xB10000007FFE03FD
