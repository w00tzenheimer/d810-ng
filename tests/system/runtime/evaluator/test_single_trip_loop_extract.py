"""System test: single-trip peel RECOGNIZER on live bogus_loops microcode.

Validates the full extraction chain end-to-end -- natural-loop membership + DU
reaching-defs + dominance (P2) + predicate orientation -> LoopFacts -> proven
gate -- against the REAL ``bogus_loops`` (``for (i=0; !i; i=1)``).  The recognizer
must extract exactly c0=0, c1=1, CONTINUE = (guard == 0), and the gate must
PROVE trip_count == 1.
"""
from __future__ import annotations

import os
import platform

import pytest

import ida_hexrays
import idaapi
import idc

from d810.analyses.control_flow.single_trip_loop import CmpKind
from d810.evaluator.hexrays_microcode.single_trip_loop_extract import (
    find_single_trip_peels,
)


def _get_default_binary() -> str:
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    system = platform.system()
    if system == "Windows":
        return "libobfuscated.dll"
    if system == "Darwin":
        return "libobfuscated.dylib"
    return "libobfuscated.so"


def get_func_ea(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    return ea


def gen_microcode_at_maturity(func_ea: int, maturity: int):
    func = idaapi.get_func(func_ea)
    if func is None:
        return None
    mbr = ida_hexrays.mba_ranges_t(func)
    hf = ida_hexrays.hexrays_failure_t()
    return ida_hexrays.gen_microcode(
        mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, maturity
    )


_MATURITIES = [
    ("CALLS", ida_hexrays.MMAT_CALLS),
    ("GLBOPT1", ida_hexrays.MMAT_GLBOPT1),
    ("GLBOPT2", ida_hexrays.MMAT_GLBOPT2),
    ("GLBOPT3", ida_hexrays.MMAT_GLBOPT3),
]


class TestSingleTripRecognizer:
    binary_name = _get_default_binary()

    def test_bogus_loops_recognized_and_proved(self, libobfuscated_setup):
        func_ea = get_func_ea("bogus_loops")
        if func_ea == idaapi.BADADDR:
            pytest.skip("bogus_loops not present in test binary")

        report: list[str] = ["", "=== single-trip recognizer: bogus_loops ==="]
        proved_maturities: list[str] = []

        for label, mat in _MATURITIES:
            mba = gen_microcode_at_maturity(func_ea, mat)
            if mba is None:
                report.append(f"[{label}] gen_microcode -> None")
                continue
            peels = find_single_trip_peels(mba)
            report.append(
                f"[{label}] proved_peels="
                f"{[(p.latch, p.header, p.verdict.trip_count) for p in peels]}"
            )
            for p in peels:
                f = p.verdict.facts
                report.append(
                    f"    {p.latch}->{p.header}: c0={f.entry_const} c1={f.inloop_const} "
                    f"cmp={f.continue_cmp.value} imm={f.continue_imm} "
                    f"trip={p.verdict.trip_count} :: {p.verdict.reason}"
                )
                # Every proved peel of bogus_loops must be the real single-trip loop.
                assert f.entry_const == 0
                assert f.inloop_const == 1
                assert f.continue_cmp is CmpKind.EQ
                assert f.continue_imm == 0
                assert p.verdict.trip_count == 1
                proved_maturities.append(label)

        print("\n".join(report))
        assert proved_maturities, (
            "recognizer proved no single-trip peel for bogus_loops:\n"
            + "\n".join(report)
        )
