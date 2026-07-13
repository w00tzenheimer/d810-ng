from __future__ import annotations

import os
from pathlib import Path

import idapro


BIN = Path(".tmp/rhad_flowchart_append_probe.bin").resolve()
FUNC_EA = 0x40A560
TAIL_START = 0x40B9A6
TAIL_END = 0x40BB75
MODE = os.environ.get("RHAD_FLOWCHART_MODE", "inspect")


assert idapro.open_database(str(BIN), True) == 0
try:
    import ida_hexrays
    import idaapi

    from d810.optimizers.microcode.flow.jumps import computed_goto_resolver as cg

    idaapi.auto_wait()
    assert ida_hexrays.init_hexrays_plugin()
    resolution = cg.resolve_and_materialize(FUNC_EA)
    assert resolution is not None
    print(
        "materialized",
        f"sites={resolution.site_count}",
        f"targets={resolution.target_count}",
        flush=True,
    )

    def hit_count(mba: object) -> int:
        hits = 0
        for serial in range(int(mba.qty)):
            block = mba.get_mblock(serial)
            instruction = block.head
            while instruction is not None:
                if TAIL_START <= int(instruction.ea) < TAIL_END:
                    hits += 1
                instruction = instruction.next
        return hits

    class FlowchartAppendProbe(ida_hexrays.Hexrays_Hooks):
        def flowchart(self, fc, mba, reachable_blocks, decomp_flags):
            if int(mba.entry_ea) != FUNC_EA:
                return 0
            before = int(fc.size())
            existing = []
            for serial in range(before):
                block = fc[serial]
                if int(block.start_ea) < TAIL_END and int(block.end_ea) > TAIL_START:
                    existing.append(
                        (
                            serial,
                            int(block.start_ea),
                            int(block.end_ea),
                            bool(reachable_blocks.has(serial)),
                        )
                    )
            after = before
            added_reachable = 0
            if MODE == "append":
                fc.append_to_flowchart(TAIL_START, TAIL_END)
                after = int(fc.size())
                candidate_serials = range(before, after)
            else:
                candidate_serials = (
                    serial
                    for serial, _start, _end, was_reachable in existing
                    if not was_reachable
                )
            for serial in candidate_serials:
                if not reachable_blocks.has(serial):
                    reachable_blocks.add(serial)
                    added_reachable += 1
            print(
                "FLOWCHART_PROBE",
                f"mode={MODE}",
                f"before={before}",
                f"after={after}",
                f"existing={existing}",
                f"added_reachable={added_reachable}",
                f"flags={int(fc.flags):#x}",
                flush=True,
            )
            return 0

        def microcode(self, mba):
            if int(mba.entry_ea) == FUNC_EA:
                print(
                    "MMAT_GENERATED",
                    f"qty={int(mba.qty)}",
                    f"hits={hit_count(mba)}",
                    flush=True,
                )
            return 0

        def preoptimized(self, mba):
            if int(mba.entry_ea) == FUNC_EA:
                print(
                    "MMAT_PREOPTIMIZED",
                    f"qty={int(mba.qty)}",
                    f"hits={hit_count(mba)}",
                    flush=True,
                )
            return 0

    hook = FlowchartAppendProbe()
    hook.hook()
    try:
        ida_hexrays.clear_cached_cfuncs()
        failure = ida_hexrays.hexrays_failure_t()
        cfunc = ida_hexrays.decompile_func(
            idaapi.get_func(FUNC_EA),
            failure,
            ida_hexrays.DECOMP_NO_CACHE,
        )
        print(
            "DECOMPILE",
            cfunc is not None,
            f"failure={failure.desc()!r}",
            flush=True,
        )
    finally:
        hook.unhook()
finally:
    idapro.close_database(False)
