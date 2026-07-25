"""Trace imported-snippet provenance around one native CFG frontier."""

from __future__ import annotations

import argparse
from collections import deque
from pathlib import Path

import idapro


FUNCTION_EA = 0x40A560
ZERO_ARG_CALLEE_EA = 0x40F830


def _parse_ea(text: str) -> int:
    return int(text, 0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--trace-ea", type=_parse_ea, required=True)
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--rounds", type=int, default=2)
    args = parser.parse_args()

    assert idapro.open_database(str(args.binary), True) == 0
    hook = None
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

        def instructions(block):
            instruction = block.head
            while instruction is not None:
                yield instruction
                if instruction is block.tail:
                    break
                instruction = instruction.next

        def block_anchor(block, origins: dict[int, int]) -> int:
            native_eas = tuple(
                int(origins.get(int(instruction.ea), int(instruction.ea)))
                for instruction in instructions(block)
                if int(origins.get(int(instruction.ea), int(instruction.ea))) > 0
            )
            return min(native_eas) if native_eas else int(block.start)

        def label(mba, serial: int, origins: dict[int, int]) -> str:
            block = mba.get_mblock(int(serial))
            return f"blk{int(serial)}@0x{block_anchor(block, origins):X}"

        class FrontierProbe(ida_hexrays.Hexrays_Hooks):
            def __init__(self) -> None:
                super().__init__()
                self.calls_callbacks = 0

            def calls_done(self, mba):
                if int(mba.entry_ea) != FUNCTION_EA:
                    return 0
                self.calls_callbacks += 1
                origins = dict(
                    detached.imported_detached_snippet_instruction_origins(mba)
                )
                identity = detached.stable_mba_identity(mba)
                roots = {
                    int(target_ea): root
                    for (mba_identity, target_ea), root in (
                        detached._IMPORTED_SNIPPET_ROOTS.items()
                    )
                    if int(mba_identity) == int(identity)
                }
                owners_by_imported_ea: dict[int, tuple[int, ...]] = {}
                for target_ea, root in roots.items():
                    for imported_ea in root.owned_instruction_eas:
                        owners_by_imported_ea.setdefault(int(imported_ea), ())
                        owners_by_imported_ea[int(imported_ea)] = (
                            *owners_by_imported_ea[int(imported_ea)],
                            int(target_ea),
                        )

                starts = tuple(
                    int(block.serial)
                    for serial in range(int(mba.qty))
                    for block in (mba.get_mblock(serial),)
                    if any(
                        int(instruction.ea) == int(args.trace_ea)
                        or int(origins.get(int(instruction.ea), 0))
                        == int(args.trace_ea)
                        for instruction in instructions(block)
                    )
                )
                print(
                    "FRONTIER_START",
                    f"callback={self.calls_callbacks}",
                    f"trace_ea=0x{int(args.trace_ea):X}",
                    f"matches={tuple(label(mba, serial, origins) for serial in starts)}",
                    flush=True,
                )

                queue = deque((serial, 0) for serial in starts)
                visited: set[int] = set()
                while queue:
                    serial, depth = queue.popleft()
                    if serial in visited or depth > int(args.depth):
                        continue
                    visited.add(serial)
                    block = mba.get_mblock(serial)
                    rows = tuple(
                        (
                            f"imported=0x{int(instruction.ea):X}",
                            f"native=0x{int(origins.get(int(instruction.ea), int(instruction.ea))):X}",
                            f"opcode={int(instruction.opcode)}",
                            f"owners={tuple(hex(ea) for ea in owners_by_imported_ea.get(int(instruction.ea), ()))}",
                            str(instruction),
                        )
                        for instruction in instructions(block)
                    )
                    predecessor_labels = tuple(
                        label(mba, int(pred), origins) for pred in block.predset
                    )
                    successor_labels = tuple(
                        label(mba, int(succ), origins) for succ in block.succset
                    )
                    print(
                        "FRONTIER_BLOCK",
                        f"callback={self.calls_callbacks}",
                        f"depth={depth}",
                        label(mba, serial, origins),
                        f"preds={predecessor_labels}",
                        f"succs={successor_labels}",
                        f"type={int(block.type)}",
                        f"rows={rows}",
                        flush=True,
                    )
                    queue.extend(
                        (int(successor), depth + 1) for successor in block.succset
                    )
                return 0

        import d810.headless as headless
        import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as cg

        headless.configure(project="default_unflattening_ollvm.json")
        headless.start()
        try:
            import d810.hexrays.mutation.detached_handler_island as detached

            hook = FrontierProbe()
            hook.hook()
            cg.install()
            try:
                for round_index in range(int(args.rounds)):
                    prepared = headless.prepare_native_preanalysis(FUNCTION_EA)
                    ida_hexrays.clear_cached_cfuncs()
                    cfunc = ida_hexrays.decompile(FUNCTION_EA)
                    print(
                        "FRONTIER_ROUND",
                        f"round={round_index}",
                        f"decompiled={cfunc is not None}",
                        flush=True,
                    )
                    if cfunc is not None:
                        print(
                            "FRONTIER_ROUND",
                            f"round={round_index}",
                            f"prepared={prepared}",
                            flush=True,
                        )
            finally:
                cg.uninstall()
        finally:
            headless.stop()
    finally:
        if hook is not None:
            hook.unhook()
        idapro.close_database(False)


if __name__ == "__main__":
    main()
