from __future__ import annotations

from pathlib import Path

import idapro
import ida_hexrays
import idaapi

from d810.hexrays.hooks.optimization_suppression import (
    suppress_d810_optimization,
)


BIN = Path(".tmp/rhad_maturity_probe.bin").resolve()
FUNC_EA = 0x40A560
TAIL_START = 0x40B9A6
TAIL_END = 0x40BB75


def mba_hits(mba: object) -> tuple[int, tuple[int, ...]]:
    hits: set[int] = set()
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        insn = block.head
        while insn is not None:
            ea = int(insn.ea)
            if TAIL_START <= ea < TAIL_END:
                hits.add(ea)
            insn = insn.next
    return int(mba.qty), tuple(sorted(hits))


def generate(label: str, ranges: object, flags: int, maturity: int) -> None:
    failure = ida_hexrays.hexrays_failure_t()
    with suppress_d810_optimization():
        mba = ida_hexrays.gen_microcode(ranges, failure, None, flags, maturity)
    if mba is None:
        print(
            f"{label} maturity={maturity} flags={flags:#x} "
            f"mba=None err={failure.desc()!r}"
        )
        return
    qty, hits = mba_hits(mba)
    print(
        f"{label} maturity={maturity} flags={flags:#x} "
        f"qty={qty} fragmented={mba.mbr.is_fragmented()} "
        f"hits={[hex(e) for e in hits]}"
    )


idapro.open_database(str(BIN), True)
try:
    import d810.headless as headless
    from d810.optimizers.microcode.flow.jumps import computed_goto_resolver as cg

    idaapi.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    headless.configure(project="default_unflattening_ollvm.json")
    headless.start()
    try:
        resolution = cg.resolve_and_materialize(FUNC_EA)
        print(
            "materialized",
            resolution is not None,
            f"sites={resolution.site_count if resolution is not None else 0}",
            f"targets={resolution.target_count if resolution is not None else 0}",
        )
        func = idaapi.get_func(FUNC_EA)
        assert func is not None
        function_ranges = ida_hexrays.mba_ranges_t(func)
        isolated_ranges = ida_hexrays.mba_ranges_t()
        isolated_ranges.ranges.push_back(idaapi.range_t(TAIL_START, TAIL_END))
        maturities = (
            ida_hexrays.MMAT_GENERATED,
            ida_hexrays.MMAT_PREOPTIMIZED,
            ida_hexrays.MMAT_LOCOPT,
            ida_hexrays.MMAT_CALLS,
        )
        for maturity in maturities:
            generate("function", function_ranges, ida_hexrays.DECOMP_NO_WAIT, maturity)
            generate(
                "function-all-blks",
                function_ranges,
                ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_ALL_BLKS,
                maturity,
            )
            generate("isolated", isolated_ranges, ida_hexrays.DECOMP_NO_WAIT, maturity)
    finally:
        headless.stop()
finally:
    idapro.close_database(False)
