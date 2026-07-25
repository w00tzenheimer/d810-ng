"""Dump the raw PREOPT block containing a native prologue selector."""

from __future__ import annotations

import os

import idapro


def _instructions(block: object) -> tuple[object, ...]:
    result: list[object] = []
    instruction = block.head
    while instruction is not None:
        result.append(instruction)
        if instruction is block.tail or instruction == block.tail:
            break
        instruction = instruction.next
    return tuple(result)


def main() -> int:
    binary = os.environ["RHAD_PROLOGUE_BIN"]
    function_ea = int(os.environ.get("RHAD_PROLOGUE_FUNC", "0x40D200"), 0)
    range_start = int(os.environ.get("RHAD_PROLOGUE_START", "0x40D240"), 0)
    range_end = int(os.environ.get("RHAD_PROLOGUE_END", "0x40D270"), 0)
    idapro.open_database(binary, True)
    try:
        import ida_hexrays
        from d810.hexrays.utils.hexrays_formatters import format_minsn_t

        ida_hexrays.init_hexrays_plugin()

        class Hooks(ida_hexrays.Hexrays_Hooks):
            def preoptimized(self, mba):
                if int(mba.entry_ea) != function_ea:
                    return 0
                for serial in range(int(mba.qty)):
                    block = mba.get_mblock(serial)
                    instructions = _instructions(block)
                    if not any(
                        range_start <= int(instruction.ea) < range_end
                        for instruction in instructions
                    ):
                        continue
                    print(
                        "BLOCK",
                        serial,
                        hex(int(block.start)),
                        hex(int(block.end)),
                        int(block.type),
                        tuple(int(succ) for succ in block.succset),
                    )
                    for instruction in instructions:
                        print(
                            "INSN",
                            hex(int(instruction.ea)),
                            int(instruction.opcode),
                            format_minsn_t(instruction),
                        )
                return 0

        hooks = Hooks()
        hooks.hook()
        try:
            ida_hexrays.decompile(function_ea)
        finally:
            hooks.unhook()
        return 0
    finally:
        idapro.close_database(False)


if __name__ == "__main__":
    raise SystemExit(main())
