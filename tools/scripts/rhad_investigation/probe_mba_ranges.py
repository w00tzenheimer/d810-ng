"""Probe Hex-Rays microcode generation for explicit native range unions.

The input is intentionally generic: a disposable binary, a function envelope,
and comma-separated ``START-END`` ranges.  The probe first runs d810 once so
resolver byte materialization is live in the IDB, then tests each range, every
cumulative prefix, and the complete union in snippet mode at PREOPT.
"""

from __future__ import annotations

import os
from pathlib import Path

import idapro


BIN = Path(os.environ["D810_RANGE_PROBE_BIN"]).resolve()
FUNCTION_EA = int(os.environ["D810_RANGE_PROBE_FUNCTION"], 0)
FUNCTION_END = int(os.environ["D810_RANGE_PROBE_END"], 0)
RANGES = tuple(
    tuple(int(part, 0) for part in item.split("-", 1))
    for item in os.environ["D810_RANGE_PROBE_RANGES"].split(",")
    if item
)
TARGET_EAS = tuple(
    int(item, 0)
    for item in os.environ.get("D810_RANGE_PROBE_TARGET_EAS", "").split(",")
    if item
)
CAPTURE_SCOPE = os.environ.get("D810_RANGE_PROBE_CAPTURE_SCOPE") == "1"
PAIR_PROBE = os.environ.get("D810_RANGE_PROBE_PAIR") == "1"
FUNCTION_MODE = os.environ.get("D810_RANGE_PROBE_FUNCTION_MODE") == "1"
PROBE_SINGLES = os.environ.get("D810_RANGE_PROBE_SINGLES", "1") == "1"
PROBE_FULL = os.environ.get("D810_RANGE_PROBE_FULL", "1") == "1"
PREFIX_COUNTS = tuple(
    int(item, 0)
    for item in os.environ.get("D810_RANGE_PROBE_PREFIX_COUNTS", "").split(",")
    if item
)
SIDECAR_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til", ".i64")


def _clear_sidecars(binary: Path) -> None:
    for suffix in SIDECAR_SUFFIXES:
        for stale in (binary.with_suffix(suffix), Path(str(binary) + suffix)):
            stale.unlink(missing_ok=True)


def _format_ranges(ranges: tuple[tuple[int, int], ...]) -> str:
    return repr(tuple((hex(start_ea), hex(end_ea)) for start_ea, end_ea in ranges))


_clear_sidecars(BIN)
assert idapro.open_database(str(BIN), True) == 0
try:
    import ida_auto
    import ida_funcs
    import ida_hexrays
    import ida_ua
    import idaapi

    import d810.headless as headless
    import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as cg

    idaapi.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    if ida_funcs.get_func(FUNCTION_EA) is None:
        ida_auto.plan_and_wait(FUNCTION_EA, FUNCTION_END)
        ida_ua.create_insn(FUNCTION_EA)
        assert ida_funcs.add_func(FUNCTION_EA, FUNCTION_END)
    function = ida_funcs.get_func(FUNCTION_EA)
    assert function is not None
    if int(function.end_ea) != FUNCTION_END:
        ida_auto.plan_and_wait(FUNCTION_EA, FUNCTION_END)
        assert ida_funcs.set_func_end(FUNCTION_EA, FUNCTION_END)
        idaapi.auto_wait()

    headless.configure(project="default_unflattening_ollvm.json")
    headless.start()
    cg.install()
    ida_hexrays.decompile(FUNCTION_EA)
    if CAPTURE_SCOPE:
        cg._SNIPPET_CAPTURE_ACTIVE = True
        cg._SNIPPET_CAPTURE_PROFILE_EA = FUNCTION_EA

    def target_rows(mba, target_ea: int):
        mba.build_graph()
        rows = []
        for serial in range(int(mba.qty)):
            block = mba.get_mblock(serial)
            instruction_rows = []
            instruction = block.head
            while instruction is not None:
                instruction_rows.append((int(instruction.ea), int(instruction.opcode)))
                instruction = instruction.next
            instruction_eas = tuple(ea for ea, _opcode in instruction_rows)
            if int(block.start) == target_ea or target_ea in instruction_eas:
                rows.append(
                    (
                        f"blk{serial}@0x{int(block.start):X}",
                        int(block.type),
                        int(block.flags),
                        tuple((hex(ea), opcode) for ea, opcode in instruction_rows),
                        tuple(int(successor) for successor in block.succset),
                    )
                )
        return rows

    def generate(label: str, ranges: tuple[tuple[int, int], ...]) -> None:
        mba_ranges = (
            ida_hexrays.mba_ranges_t(function)
            if FUNCTION_MODE
            else ida_hexrays.mba_ranges_t()
        )
        if not FUNCTION_MODE:
            for start_ea, end_ea in ranges:
                mba_ranges.ranges.push_back(idaapi.range_t(start_ea, end_ea))
        failure = ida_hexrays.hexrays_failure_t()
        mba = cg._generate_microcode_without_d810(
            ida_hexrays.gen_microcode,
            mba_ranges,
            failure,
            None,
            int(ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_ALL_BLKS),
            int(ida_hexrays.MMAT_PREOPTIMIZED),
        )
        print(
            "RANGE_PROBE",
            f"label={label}",
            f"ranges={_format_ranges(ranges)}",
            f"ok={mba is not None}",
            f"failure={failure.desc()!r}",
            f"errea=0x{int(failure.errea):X}",
            f"qty={None if mba is None else int(mba.qty)}",
            flush=True,
        )
        if mba is None or not TARGET_EAS:
            return
        for target_ea in TARGET_EAS:
            print(
                "RANGE_TARGET",
                f"label={label}",
                f"target=0x{target_ea:X}",
                f"rows={target_rows(mba, target_ea)!r}",
                flush=True,
            )

    def generate_pair(ranges: tuple[tuple[int, int], ...]) -> None:
        mba_ranges = ida_hexrays.mba_ranges_t()
        for start_ea, end_ea in ranges:
            mba_ranges.ranges.push_back(idaapi.range_t(start_ea, end_ea))

        def at(maturity: int):
            failure = ida_hexrays.hexrays_failure_t()
            mba = cg._generate_microcode_without_d810(
                ida_hexrays.gen_microcode,
                mba_ranges,
                failure,
                None,
                int(ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_ALL_BLKS),
                maturity,
            )
            print(
                "PAIR_GENERATE",
                f"maturity={maturity}",
                f"ok={mba is not None}",
                f"failure={failure.desc()!r}",
                flush=True,
            )
            return mba

        preopt = at(int(ida_hexrays.MMAT_PREOPTIMIZED))
        for target_ea in TARGET_EAS:
            print(
                "PAIR_TARGET",
                "stage=preopt_before_calls",
                f"target=0x{target_ea:X}",
                f"rows={target_rows(preopt, target_ea)!r}",
                flush=True,
            )
        calls = at(int(ida_hexrays.MMAT_CALLS))
        for label, mba in (("preopt_after_calls", preopt), ("calls", calls)):
            for target_ea in TARGET_EAS:
                print(
                    "PAIR_TARGET",
                    f"stage={label}",
                    f"target=0x{target_ea:X}",
                    f"rows={target_rows(mba, target_ea)!r}",
                    flush=True,
                )

    if PROBE_SINGLES:
        for index, native_range in enumerate(RANGES):
            generate(f"single-{index}", (native_range,))
    prefix_counts = PREFIX_COUNTS if PREFIX_COUNTS else tuple(range(2, len(RANGES) + 1))
    for count in prefix_counts:
        if count < 1 or count > len(RANGES):
            raise ValueError(f"prefix count {count} outside 1..{len(RANGES)}")
        generate(f"prefix-{count}", RANGES[:count])
    if PROBE_FULL:
        generate("full", RANGES)
    if PAIR_PROBE:
        generate_pair(RANGES)
finally:
    if "cg" in globals() and CAPTURE_SCOPE:
        cg._SNIPPET_CAPTURE_ACTIVE = False
        cg._SNIPPET_CAPTURE_PROFILE_EA = None
    idapro.close_database(False)
