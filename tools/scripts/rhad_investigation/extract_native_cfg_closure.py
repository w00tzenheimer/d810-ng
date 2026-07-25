#!/usr/bin/env python3
"""Extract an EA-anchored native CFG closure from a rewritten PE image.

This is an investigation oracle, not a d810 implementation component.  It
walks direct x86 control flow in a neighboring-tool-patched binary so imported
microcode can be compared beyond IDA's original function boundary.  Unknown
indirect transfers are explicit cut points; no edge is guessed.
"""

from __future__ import annotations

import argparse
from collections import deque
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_GRP_JUMP, X86_INS_CALL, X86_INS_RET, X86_OP_IMM
import pefile


def _parse_ea(value: str) -> int:
    return int(value, 0)


def _decode_one(disassembler: Cs, image: bytes, pe: pefile.PE, ea: int):
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    offset = int(pe.get_offset_from_rva(int(ea) - image_base))
    return next(disassembler.disasm(image[offset : offset + 16], int(ea), 1), None)


def extract_closure(binary: Path, seeds: tuple[int, ...]) -> dict[str, object]:
    image = binary.read_bytes()
    pe = pefile.PE(data=image, fast_load=True)
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True

    pending = deque(sorted(set(int(seed) for seed in seeds)))
    visited: set[int] = set()
    instructions: list[dict[str, object]] = []
    edges: set[tuple[int, int, str]] = set()
    cut_points: list[dict[str, object]] = []

    while pending:
        ea = pending.popleft()
        if ea in visited:
            continue
        instruction = _decode_one(disassembler, image, pe, ea)
        if instruction is None:
            cut_points.append({"ea": f"0x{ea:X}", "reason": "decode_failed"})
            continue
        visited.add(ea)
        next_ea = int(instruction.address + instruction.size)
        instructions.append(
            {
                "ea": f"0x{int(instruction.address):X}",
                "bytes": instruction.bytes.hex(),
                "mnemonic": instruction.mnemonic,
                "op_str": instruction.op_str,
            }
        )

        if instruction.id == X86_INS_RET:
            continue
        if instruction.id == X86_INS_CALL:
            edges.add((ea, next_ea, "fallthrough"))
            pending.append(next_ea)
            continue
        if instruction.group(X86_GRP_JUMP):
            if not instruction.operands or instruction.operands[0].type != X86_OP_IMM:
                cut_points.append(
                    {"ea": f"0x{ea:X}", "reason": "unknown_indirect_jump"}
                )
                continue
            target = int(instruction.operands[0].imm)
            edges.add((ea, target, "taken"))
            pending.append(target)
            if instruction.mnemonic != "jmp":
                edges.add((ea, next_ea, "fallthrough"))
                pending.append(next_ea)
            continue
        edges.add((ea, next_ea, "fallthrough"))
        pending.append(next_ea)

    return {
        "binary": str(binary),
        "seeds": [f"0x{ea:X}" for ea in sorted(set(seeds))],
        "instruction_count": len(instructions),
        "instructions": sorted(instructions, key=lambda row: int(str(row["ea"]), 16)),
        "edges": [
            {"source_ea": f"0x{source:X}", "target_ea": f"0x{target:X}", "kind": kind}
            for source, target, kind in sorted(edges)
        ],
        "cut_points": sorted(cut_points, key=lambda row: int(str(row["ea"]), 16)),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("seed_ea", nargs="+", type=_parse_ea)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = extract_closure(args.binary.resolve(), tuple(args.seed_ea))
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(text, end="")
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
