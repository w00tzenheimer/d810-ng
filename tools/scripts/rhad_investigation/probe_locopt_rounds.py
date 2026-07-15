"""Measure repeated production LOCOPT/CALLS decompilation of sub_40A560."""
from __future__ import annotations

import argparse
from pathlib import Path
import re

import idapro


FUNCTION_EA = 0x40A560
ZERO_ARG_CALLEE_EA = 0x40F830


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--rounds", type=int, default=4)
    args = parser.parse_args()

    assert idapro.open_database(str(args.binary), True) == 0
    recovered = "None"
    try:
        import ida_hexrays
        import idaapi
        import idc

        idaapi.auto_wait()
        assert ida_hexrays.init_hexrays_plugin()
        assert idc.SetType(
            ZERO_ARG_CALLEE_EA,
            "int __cdecl sub_40F830(void)",
        )

        import d810.headless as headless

        headless.configure(project="default_unflattening_ollvm.json")
        headless.start()
        try:
            import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as cg
            from d810.hexrays.mutation.detached_handler_island import (
                imported_detached_snippet_instruction_origins,
            )
            from d810.hexrays.preanalysis.indirect_jump_labels import (
                mark_indirect_dispatcher,
            )

            cg.install()
            try:
                for round_index in range(args.rounds):
                    mark_indirect_dispatcher(FUNCTION_EA)
                    ida_hexrays.clear_cached_cfuncs()
                    cfunc = ida_hexrays.decompile(FUNCTION_EA)
                    print(
                        "LOCOPT_ROUND",
                        round_index,
                        "decompiled",
                        cfunc is not None,
                        flush=True,
                    )
                    if cfunc is None:
                        continue
                    recovered = str(cfunc)
                    origins = dict(
                        imported_detached_snippet_instruction_origins(
                            cfunc.mba
                        )
                    )
                    jumpout_eas = {
                        int(match, 16)
                        for match in re.findall(
                            r"JUMPOUT\(0x([0-9A-Fa-f]+)\)",
                            recovered,
                        )
                    }
                    for serial in range(int(cfunc.mba.qty)):
                        block = cfunc.mba.get_mblock(serial)
                        instruction = block.head
                        instruction_rows = []
                        while instruction is not None:
                            instruction_rows.append(
                                (
                                    hex(int(instruction.ea)),
                                    hex(int(origins.get(int(instruction.ea), 0))),
                                    int(instruction.opcode),
                                    str(instruction),
                                )
                            )
                            if instruction is block.tail:
                                break
                            instruction = instruction.next
                        if not jumpout_eas.intersection(
                            int(row[0], 16) for row in instruction_rows
                        ):
                            continue
                        print(
                            "LOCOPT_JUMPOUT_BLOCK",
                            round_index,
                            f"blk{int(block.serial)}@0x{int(block.start):X}",
                            "preds",
                            tuple(int(pred) for pred in block.predset),
                            "succs",
                            tuple(int(succ) for succ in block.succset),
                            "instructions",
                            tuple(instruction_rows),
                            flush=True,
                        )
                    captured = cg.prepare_detached_handler_snippets(
                        FUNCTION_EA,
                        live_mba=cfunc.mba,
                    )
                    print(
                        "LOCOPT_ROUND",
                        round_index,
                        "captured",
                        captured,
                        flush=True,
                    )
            finally:
                cg.uninstall()
        finally:
            headless.stop()
    finally:
        idapro.close_database(False)

    args.output.write_text(recovered, encoding="utf-8")


if __name__ == "__main__":
    main()
