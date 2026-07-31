#!/usr/bin/env python3
"""Build the exact A560 constant-materialization reference inventory.

The pinned Rhad implementation performs jump reconstruction before constant
materialization.  This tool executes that ordering on an in-memory copy, then
uses the reference ``ConstantInliner`` classifier and ``filter_outliers``
function unchanged.  It never patches the input binary or the reference
checkout.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import io
import json
from pathlib import Path
import subprocess
import sys


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference-checkout", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument(
        "--function-start",
        type=lambda value: int(value, 0),
        required=True,
    )
    parser.add_argument(
        "--function-end",
        type=lambda value: int(value, 0),
        required=True,
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def _reference_commit(checkout: Path) -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _encoding_variant(insn: object) -> str:
    mnemonic = str(insn.mnemonic)
    raw = bytes(insn.bytes)
    if mnemonic == "add" and raw[0] == 0x03:
        return "add_r32_absolute"
    if mnemonic == "xor" and raw[0] == 0x32:
        return "xor_r8_absolute"
    if mnemonic == "movzx" and raw[:2] == b"\x0f\xb6":
        return "movzx_r32_byte_absolute"
    if mnemonic == "movzx" and raw[:2] == b"\x0f\xb7":
        return "movzx_r32_word_absolute"
    if mnemonic == "mov" and raw[0] == 0xA1:
        return "mov_eax_absolute"
    if mnemonic == "mov" and raw[0] == 0x8B:
        return "mov_r32_absolute"
    raise ValueError(f"unsupported admitted reference encoding: {raw.hex()}")


def _operation_variant(insn: object) -> str:
    return {
        "add": "add_absolute",
        "mov": "mov_absolute",
        "movzx": "movzx_absolute",
        "xor": "xor_absolute",
    }[str(insn.mnemonic)]


def _reference_symbol(insn: object) -> str:
    if str(insn.mnemonic) in {"mov", "movzx"}:
        return "deob_consts.ConstantInliner.transform_mov_mem_to_imm"
    return "deob_consts.ConstantInliner.transform_arith_mem_to_imm"


def _inventory_rows(
    blob: bytearray,
    pe: object,
    *,
    function_start: int,
    function_end: int,
) -> tuple[list[dict[str, object]], int, int]:
    deob_consts = importlib.import_module("deob_consts")
    deob_util = importlib.import_module("deob_util")
    raw = int(pe.sections[0].PointerToRawData)
    raw_size = int(pe.sections[0].SizeOfRawData)
    text_ea = int(pe.OPTIONAL_HEADER.ImageBase) + int(pe.sections[0].VirtualAddress)
    instructions = deob_util.ContinuousDisassembler().disassemble_all(
        blob[raw : raw + raw_size],
        text_ea,
    )
    inliner = deob_consts.ConstantInliner(blob, instructions, pe)
    loads = [
        instruction
        for instruction in instructions.values()
        if inliner.is_acceptable_load(instruction)
    ]
    candidate_data_eas = sorted(
        {
            int(instruction.operands[1].value.mem.disp) for instruction in loads
        }
    )
    with contextlib.redirect_stdout(io.StringIO()):
        accepted_data_eas = set(deob_consts.filter_outliers(candidate_data_eas))

    admitted = [
        instruction
        for instruction in loads
        if int(instruction.operands[1].value.mem.disp) in accepted_data_eas
        and function_start <= int(instruction.address) < function_end
    ]
    rows: list[dict[str, object]] = []
    for reference_order, instruction in enumerate(admitted):
        instruction_ea = int(instruction.address)
        data_ea = int(instruction.operands[1].value.mem.disp)
        data_bytes = bytes(
            blob[
                data_ea - inliner.raw_virt_delta_data :
                data_ea - inliner.raw_virt_delta_data + 4
            ]
        )
        raw_value = int.from_bytes(data_bytes, "little")
        source_width_bits = int(instruction.operands[1].size) * 8
        effective_value = raw_value & ((1 << source_width_bits) - 1)
        if str(instruction.mnemonic) in {"mov", "movzx"}:
            replacement = inliner.transform_mov_mem_to_imm(
                bytes(instruction.bytes),
                raw_value,
            )
        else:
            replacement = inliner.transform_arith_mem_to_imm(
                bytes(instruction.bytes),
                raw_value,
            )
        rows.append(
            {
                "reference_order": reference_order,
                "operation_id": f"rhad:constant@0x{instruction_ea:X}",
                "operation_variant": _operation_variant(instruction),
                "encoding_variant": _encoding_variant(instruction),
                "reference_symbol": _reference_symbol(instruction),
                "source_native_ea": instruction_ea,
                "source_instruction_bytes": bytes(instruction.bytes).hex(),
                "source_operand_path": "operand[1].absolute_memory",
                "source_width_bits": source_width_bits,
                "destination_register": instruction.reg_name(
                    int(instruction.operands[0].reg)
                ),
                "destination_width_bits": int(instruction.operands[0].size) * 8,
                "data_native_ea": data_ea,
                "reference_read_width_bits": 32,
                "reference_data_bytes_le": data_bytes.hex(),
                "reference_raw_value": raw_value,
                "materialized_value": effective_value,
                "replacement_instruction_bytes": replacement.hex(),
                "current_compiler_support": "unsupported_typed_shape",
                "current_generated_proof": {"status": "unproved"},
            }
        )
    return rows, len(candidate_data_eas), len(accepted_data_eas)


def main() -> None:
    args = _arguments()
    reference = args.reference_checkout.resolve()
    binary = args.binary.resolve()
    output = args.output.resolve()
    reference_commit = _reference_commit(reference)
    sys.path.insert(0, str(reference))
    pefile = importlib.import_module("pefile")
    deob_jumps = importlib.import_module("deob_jumps")

    original = bytearray(binary.read_bytes())
    pe = pefile.PE(data=original, fast_load=True)
    before, candidate_count, accepted_count = _inventory_rows(
        original,
        pe,
        function_start=args.function_start,
        function_end=args.function_end,
    )
    jump_reconstructed = bytearray(original)
    with contextlib.redirect_stdout(io.StringIO()):
        deob_jumps.deobfuscate_function(
            jump_reconstructed,
            pe,
            args.function_start,
        )
    after, post_candidate_count, post_accepted_count = _inventory_rows(
        jump_reconstructed,
        pe,
        function_start=args.function_start,
        function_end=args.function_end,
    )
    if before != after:
        raise RuntimeError(
            "A560 constant inventory changed after reference jump reconstruction"
        )
    if (candidate_count, accepted_count) != (
        post_candidate_count,
        post_accepted_count,
    ):
        raise RuntimeError("reference whole-image constant classifier drifted")

    operations_json = json.dumps(after, sort_keys=True, separators=(",", ":"))
    variant_counts: dict[str, int] = {}
    for operation in after:
        variant = str(operation["operation_variant"])
        variant_counts[variant] = variant_counts.get(variant, 0) + 1
    payload = {
        "schema_version": 1,
        "reference_commit": reference_commit,
        "input_sha256": hashlib.sha256(original).hexdigest(),
        "function_ea": args.function_start,
        "function_end_ea": args.function_end,
        "reference_phase": "constant_materialization",
        "reference_phase_order": 1,
        "reference_pipeline_order": [
            "deob_jumps.deobfuscate_function",
            "deob_consts.ConstantInliner.deobfuscate",
        ],
        "selection_contract": {
            "candidate_predicate": "ConstantInliner.is_acceptable_load",
            "candidate_scope": "whole .text",
            "data_cluster_filter": "filter_outliers",
            "max_step": 16,
            "min_cluster_size": 10,
            "reference_iteration_order": "ascending native instruction EA",
            "whole_image_unique_candidate_data_ea_count": candidate_count,
            "whole_image_accepted_data_ea_count": accepted_count,
        },
        "operation_count": len(after),
        "operation_variant_counts": dict(sorted(variant_counts.items())),
        "operations_identity": "sha256:"
        + hashlib.sha256(operations_json.encode("utf-8")).hexdigest(),
        "operations": after,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
