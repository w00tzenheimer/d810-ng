"""Compiled-CFG validation for Hex-Rays structuring lab fixtures."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

import pytest

from tests.system.runtime.conftest import gen_microcode_at_maturity, get_func_ea


DEFAULT_CASE_ID = "single_pred_chain_merge"
DEFAULT_FUNCTION = "hexrays_lab_single_pred_chain_merge"
DEFAULT_OUTPUT_JSON = (
    ".tmp/hexrays_structuring_lab/cfg_validation/"
    "single_pred_chain_merge.json"
)
EXPECTED_MATURITY = "MMAT_LOCOPT"
EXPECTED_BLOCK_COUNT = 6
EXPECTED_CHAIN_LENGTH = 6
EXPECTED_CHAIN_TYPES = [
    "BLT_1WAY",
    "BLT_1WAY",
    "BLT_1WAY",
    "BLT_1WAY",
    "BLT_1WAY",
    "BLT_STOP",
]
EXPECTED_BODY_RELATIVE_STARTS = [
    "0x0",
    "0x33",
    "0x1f",
    "0x11",
]
EXPECTED_BODY_OPCODE_SIGNATURES = [
    [4, 25, 26, 33, 31, 29, 9, 12, 55],
    [9, 14, 4, 4, 33, 31, 29, 21, 9, 4, 55],
    [25, 26, 33, 31, 29, 13, 9, 4, 55],
    [4, 9, 4, 55],
]
MULTI_PRED_FUNCTION = "hexrays_lab_multi_pred_boundary_barrier"
MULTI_PRED_OUTPUT_JSON = (
    ".tmp/hexrays_structuring_lab/cfg_validation/"
    "multi_pred_boundary_barrier.json"
)
MULTI_PRED_EXPECTED_BLOCK_COUNT = 9
MULTI_PRED_BOUNDARY_RELATIVE_START = "0x55"
MULTI_PRED_BOUNDARY_OPCODE_SIGNATURE = [4, 4, 33, 31, 29, 21, 9, 4, 55]
MULTI_PRED_BOUNDARY_INCOMING_RELATIVE_STARTS = ["0x1b", "0x41"]
MULTI_PRED_BOUNDARY_SUCCESSOR_RELATIVE_START = "0x2d"
MULTI_PRED_BODY_OPCODE_SIGNATURES = {
    "0x0": [4, 12, 9, 35, 30, 33, 31, 29, 43],
    "0x1b": [4, 55],
    "0x1d": [55],
    "0x1f": [4, 9, 4, 55],
    "0x2d": [25, 26, 33, 31, 29, 13, 9, 4, 55],
    "0x41": [9, 14, 9, 4],
    "0x55": MULTI_PRED_BOUNDARY_OPCODE_SIGNATURE,
}
SIDE_EFFECT_FUNCTION = "hexrays_lab_side_effect_boundary_anchor"
SIDE_EFFECT_OUTPUT_JSON = (
    ".tmp/hexrays_structuring_lab/cfg_validation/"
    "side_effect_boundary_anchor.json"
)
SIDE_EFFECT_HELPER_FUNCTION = "hexrays_lab_boundary_anchor_helper"
SIDE_EFFECT_EXPECTED_BLOCK_COUNT = 10
SIDE_EFFECT_BOUNDARY_RELATIVE_START = "0x64"
SIDE_EFFECT_BOUNDARY_OPCODE_SIGNATURE = [
    4,
    4,
    33,
    31,
    29,
    9,
    21,
    9,
    4,
    56,
]
SIDE_EFFECT_BOUNDARY_INCOMING_RELATIVE_STARTS = ["0x1f", "0x4d"]
SIDE_EFFECT_BOUNDARY_SUCCESSOR_RELATIVE_START = "0x81"
SIDE_EFFECT_BODY_OPCODE_SIGNATURES = {
    "0x0": [4, 12, 9, 35, 30, 33, 31, 29, 43],
    "0x1f": [4, 55],
    "0x21": [55],
    "0x23": [4, 9, 55],
    "0x36": [25, 26, 33, 31, 29, 13, 9, 4, 55],
    "0x4d": [9, 14, 9, 4],
    "0x64": SIDE_EFFECT_BOUNDARY_OPCODE_SIGNATURE,
    "0x81": [4, 55],
}
CLEAN_FORK_FUNCTION = "hexrays_lab_clean_conditional_fork"
CLEAN_FORK_OUTPUT_JSON = (
    ".tmp/hexrays_structuring_lab/cfg_validation/"
    "clean_conditional_fork.json"
)
CLEAN_FORK_EXPECTED_BLOCK_COUNT = 9
CLEAN_FORK_ENTRY_RELATIVE_START = "0x0"
CLEAN_FORK_ENTRY_OPCODE_SIGNATURE = [4, 12, 9, 4, 4, 33, 31, 4, 44]
CLEAN_FORK_ENTRY_SUCCESSOR_RELATIVE_STARTS = ["0x1c", "0x1e"]
CLEAN_FORK_ARM_PATHS_RELATIVE_STARTS = [
    ["0x1c", "0x58", "0x2e"],
    ["0x1e", "0x44", "0x2e"],
]
CLEAN_FORK_JOIN_RELATIVE_START = "0x2e"
CLEAN_FORK_JOIN_OPCODE_SIGNATURE = [4, 4, 33, 31, 29, 21, 9, 4, 55]
CLEAN_FORK_JOIN_INCOMING_RELATIVE_STARTS = ["0x44", "0x58"]
CLEAN_FORK_JOIN_SUCCESSOR_RELATIVE_START = "0x20"
CLEAN_FORK_BODY_OPCODE_SIGNATURES = {
    "0x0": CLEAN_FORK_ENTRY_OPCODE_SIGNATURE,
    "0x1c": [55],
    "0x1e": [55],
    "0x20": [4, 9, 4, 55],
    "0x2e": CLEAN_FORK_JOIN_OPCODE_SIGNATURE,
    "0x44": [25, 26, 33, 31, 29, 13, 9, 4, 55],
    "0x58": [25, 26, 33, 31, 29, 12, 9, 4, 55],
}
CONDITIONAL_SHELL_FUNCTION = "hexrays_lab_conditional_shell_boundary"
CONDITIONAL_SHELL_OUTPUT_JSON = (
    ".tmp/hexrays_structuring_lab/cfg_validation/"
    "conditional_shell_boundary.json"
)
CONDITIONAL_SHELL_EXPECTED_BLOCK_COUNT = 13
CONDITIONAL_SHELL_ENTRY_RELATIVE_START = "0x0"
CONDITIONAL_SHELL_ENTRY_OPCODE_SIGNATURE = [
    4,
    12,
    9,
    35,
    30,
    33,
    31,
    29,
    43,
]
CONDITIONAL_SHELL_ENTRY_SUCCESSOR_RELATIVE_STARTS = ["0x1b", "0x1d"]
CONDITIONAL_SHELL_ENTRY_TO_SHELL_PATHS_RELATIVE_STARTS = [
    ["0x1b", "0x76"],
    ["0x1d", "0x62", "0x76"],
]
CONDITIONAL_SHELL_RELATIVE_START = "0x76"
CONDITIONAL_SHELL_OPCODE_SIGNATURE = [9, 4, 4, 33, 31, 4, 44]
CONDITIONAL_SHELL_INCOMING_RELATIVE_STARTS = ["0x1b", "0x62"]
CONDITIONAL_SHELL_SUCCESSOR_RELATIVE_STARTS = ["0x84", "0x86"]
CONDITIONAL_SHELL_ARM_PATHS_RELATIVE_STARTS = [
    ["0x84", "0x57", "0x41"],
    ["0x86", "0x41"],
]
CONDITIONAL_SHELL_BOUNDARY_RELATIVE_START = "0x41"
CONDITIONAL_SHELL_BOUNDARY_OPCODE_SIGNATURE = [
    4,
    4,
    33,
    31,
    29,
    21,
    9,
    4,
    55,
]
CONDITIONAL_SHELL_BOUNDARY_INCOMING_RELATIVE_STARTS = ["0x57", "0x86"]
CONDITIONAL_SHELL_BOUNDARY_SUCCESSOR_RELATIVE_START = "0x2d"
CONDITIONAL_SHELL_BODY_OPCODE_SIGNATURES = {
    "0x0": CONDITIONAL_SHELL_ENTRY_OPCODE_SIGNATURE,
    "0x1b": [4, 55],
    "0x1d": [55],
    "0x1f": [4, 9, 4, 55],
    "0x2d": [25, 26, 33, 31, 29, 13, 9, 4, 55],
    "0x41": CONDITIONAL_SHELL_BOUNDARY_OPCODE_SIGNATURE,
    "0x57": [9, 4, 55],
    "0x62": [9, 14, 9, 4],
    "0x76": CONDITIONAL_SHELL_OPCODE_SIGNATURE,
    "0x84": [55],
    "0x86": [55],
}
BADWHILE_TRIANGLE_CASES = {
    "badwhile_direct_triangle_case": {
        "function": "hexrays_lab_badwhile_direct_triangle_case_asm",
        "output_json": (
            ".tmp/hexrays_structuring_lab/cfg_validation/"
            "badwhile_direct_triangle_case.json"
        ),
        "variant": "direct",
        "expected": {
            "accepted_maturity": EXPECTED_MATURITY,
            "shape": "father -> dispatcher -> case_cond and father -> case_cond",
            "edge_predicates": [
                "father has direct successors dispatcher and case_cond",
                "dispatcher has case_cond as a direct successor",
                "case_cond has BLT_2WAY type with nsucc == 2",
                "case_cond direct predecessors include father and dispatcher",
                "father -> case_cond is a direct edge with no one-way trampoline",
            ],
        },
    },
    "badwhile_trampoline_triangle_case": {
        "function": "hexrays_lab_badwhile_trampoline_triangle_case_asm",
        "output_json": (
            ".tmp/hexrays_structuring_lab/cfg_validation/"
            "badwhile_trampoline_triangle_case.json"
        ),
        "variant": "trampoline",
        "expected": {
            "accepted_maturity": EXPECTED_MATURITY,
            "shape": "father -> tri_trampoline -> case_cond and father -> dispatcher -> case_cond",
            "edge_predicates": [
                "father has direct successors dispatcher and tri_trampoline",
                "tri_trampoline has nsucc == 1 and reaches case_cond",
                "tri_trampoline is minimal/goto-like",
                "dispatcher has case_cond as a direct successor",
                "case_cond has BLT_2WAY type with nsucc == 2",
                "case_cond does not list father as a direct predecessor",
            ],
        },
    },
    "badwhile_duplicate_group_triangle": {
        "function": "hexrays_lab_badwhile_duplicate_group_triangle_asm",
        "output_json": (
            ".tmp/hexrays_structuring_lab/cfg_validation/"
            "badwhile_duplicate_group_triangle.json"
        ),
        "variant": "duplicate_group",
        "expected": {
            "accepted_maturity": EXPECTED_MATURITY,
            "shape": "pred_a/pred_b -> shared -> dispatcher -> case_cond with direct pred_a/pred_b -> case_cond edges",
            "edge_predicates": [
                "shared has exactly two direct predecessors",
                "pred_a and pred_b both have direct successors shared and case_cond",
                "shared has dispatcher as its only direct successor",
                "dispatcher has case_cond as a direct successor",
                "case_cond has BLT_2WAY type with nsucc == 2",
                "case_cond direct predecessors include pred_a, pred_b, and dispatcher",
            ],
        },
    },
}
TERMINAL_TAIL_REF_EXPECTED_BLOCK_COUNT = 22
TERMINAL_TAIL_REF_GUARD_RELATIVE_STARTS = [
    "0x0",
    "0x4d",
    "0x87",
    "0xc1",
    "0xfb",
    "0x132",
]
TERMINAL_TAIL_REF_RETURN_RELATIVE_STARTS = [
    "0x3e",
    "0x78",
    "0xb2",
    "0xec",
    "0x126",
    "0x15d",
]
TERMINAL_TAIL_REF_CONTINUE_RELATIVE_STARTS = [
    "0x4b",
    "0x85",
    "0xbf",
    "0xf9",
    "0x130",
    "0x167",
]
TERMINAL_TAIL_REF_FINAL_EMIT_RELATIVE_START = "0x169"
TERMINAL_TAIL_REF_RETURN_EPILOGUE_RELATIVE_START = "0x18a"
TERMINAL_TAIL_REF_FIRST_GUARD_OPCODE_SIGNATURE = [
    4,
    4,
    4,
    12,
    1,
    12,
    9,
    35,
    30,
    33,
    31,
    29,
    43,
]
TERMINAL_TAIL_REF_GUARD_OPCODE_SIGNATURE = [
    12,
    1,
    12,
    9,
    35,
    30,
    33,
    31,
    29,
    43,
]
TERMINAL_TAIL_REF_RETURN_OPCODE_SIGNATURE = [4, 4, 55]
TERMINAL_TAIL_REF_FINAL_EMIT_OPCODE_SIGNATURE = [
    25,
    26,
    33,
    31,
    29,
    12,
    1,
    9,
    4,
    4,
]
TERMINAL_TAIL_REF_RETURN_EPILOGUE_OPCODE_SIGNATURE = [9]
TERMINAL_TAIL_SHARED_EXPECTED_BLOCK_COUNT = 26
TERMINAL_TAIL_SHARED_GUARD_RELATIVE_START = "0x1e"
TERMINAL_TAIL_SHARED_EARLY_RETURN_RELATIVE_START = "0x32"
TERMINAL_TAIL_SHARED_STAGE_DISPATCH_START = "0x3e"
TERMINAL_TAIL_SHARED_RETURN_EPILOGUE_RELATIVE_START = "0x192"
TERMINAL_TAIL_SHARED_BYTE_EMIT_RELATIVE_STARTS = [
    "0x94",
    "0xb9",
    "0xdf",
    "0x105",
    "0x12b",
    "0x151",
    "0x177",
]
TERMINAL_TAIL_SHARED_STAGE_ASSIGN_RELATIVE_STARTS = [
    "0x44",
    "0x4c",
    "0x57",
    "0x62",
    "0x6d",
    "0x78",
]
TERMINAL_TAIL_SHARED_GUARD_OPCODE_SIGNATURE = [9, 35, 30, 33, 31, 29, 43]
TERMINAL_TAIL_SHARED_BYTE_EMIT_OPCODE_SIGNATURE = [
    12,
    1,
    25,
    26,
    33,
    31,
    29,
    9,
    12,
    4,
    55,
]
TERMINAL_TAIL_SHARED_FINAL_EMIT_OPCODE_SIGNATURE = [
    25,
    26,
    33,
    31,
    29,
    12,
    4,
    1,
    4,
    55,
]
TERMINAL_TAIL_SPLIT_EXPECTED_BLOCK_COUNT = 22
TERMINAL_TAIL_SPLIT_GUARD_RELATIVE_STARTS = [
    "0x0",
    "0x4e",
    "0x88",
    "0xc2",
    "0xfc",
    "0x133",
]
TERMINAL_TAIL_SPLIT_RETURN_RELATIVE_STARTS = [
    "0x3f",
    "0x79",
    "0xb3",
    "0xed",
    "0x127",
    "0x15e",
]
TERMINAL_TAIL_SPLIT_CONTINUE_RELATIVE_STARTS = [
    "0x4c",
    "0x86",
    "0xc0",
    "0xfa",
    "0x131",
    "0x168",
]
TERMINAL_TAIL_SPLIT_FINAL_EMIT_RELATIVE_START = "0x16a"
TERMINAL_TAIL_SPLIT_RETURN_EPILOGUE_RELATIVE_START = "0x18b"
TERMINAL_TAIL_UNIQUE_EXPECTED_BLOCK_COUNT = 26
TERMINAL_TAIL_UNIQUE_GUARD_RELATIVE_START = "0x2a"
TERMINAL_TAIL_UNIQUE_EARLY_RETURN_RELATIVE_START = "0x3f"
TERMINAL_TAIL_UNIQUE_STAGE_DISPATCH_START = "0x4c"
TERMINAL_TAIL_UNIQUE_RETURN_EPILOGUE_RELATIVE_START = "0x204"
TERMINAL_TAIL_UNIQUE_BYTE_EMIT_RELATIVE_STARTS = [
    "0xab",
    "0xdd",
    "0x110",
    "0x143",
    "0x176",
    "0x1a9",
    "0x1dc",
]
TERMINAL_TAIL_UNIQUE_STAGE_ASSIGN_RELATIVE_STARTS = [
    "0x53",
    "0x5f",
    "0x6b",
    "0x77",
    "0x83",
    "0x8f",
]
TERMINAL_TAIL_UNIQUE_FIRST_BYTE_EMIT_OPCODE_SIGNATURE = [
    12,
    1,
    12,
    4,
    4,
    4,
    33,
    31,
    29,
    9,
    4,
    55,
]
TERMINAL_TAIL_UNIQUE_BYTE_EMIT_OPCODE_SIGNATURE = [
    12,
    1,
    12,
    4,
    25,
    26,
    33,
    31,
    29,
    9,
    12,
    55,
]
TERMINAL_TAIL_UNIQUE_FINAL_EMIT_OPCODE_SIGNATURE = [
    12,
    1,
    4,
    25,
    26,
    33,
    31,
    29,
    9,
    12,
    55,
]
TERMINAL_TAIL_CASES = {
    "terminal_tail_ref_cascade": {
        "function": "hexrays_lab_terminal_tail_ref_cascade",
        "output_json": (
            ".tmp/hexrays_structuring_lab/cfg_validation/"
            "terminal_tail_ref_cascade.json"
        ),
        "expected": {
            "accepted_maturity": EXPECTED_MATURITY,
            "block_count": f"== {TERMINAL_TAIL_REF_EXPECTED_BLOCK_COUNT}",
            "byte_emit_count": "== 7",
            "early_return_guard_count": "== 6",
            "terminal_region": "acyclic",
            "largest_scc_size": "== 1",
            "guard_relative_start_eas": TERMINAL_TAIL_REF_GUARD_RELATIVE_STARTS,
            "early_return_relative_start_eas": (
                TERMINAL_TAIL_REF_RETURN_RELATIVE_STARTS
            ),
            "continue_relative_start_eas": (
                TERMINAL_TAIL_REF_CONTINUE_RELATIVE_STARTS
            ),
            "final_emit_relative_start_ea": (
                TERMINAL_TAIL_REF_FINAL_EMIT_RELATIVE_START
            ),
            "return_epilogue_relative_start_ea": (
                TERMINAL_TAIL_REF_RETURN_EPILOGUE_RELATIVE_START
            ),
            "edge_predicates": [
                "byte emit blocks appear in index order base+0 through base+6",
                "each byte emit base+0 through base+5 reaches its own early-return guard before the next byte emit",
                "guard0 through guard5 each have one return arm and one continue arm",
                "the continue arm from guard[k] reaches byte[k + 1] through a distinct empty handoff",
                "byte6 reaches the shared return epilogue",
                "the shared return epilogue has exactly seven incoming returns and contains only the return-value xdu",
            ],
        },
    },
    "terminal_tail_shared_convergence": {
        "function": "hexrays_lab_terminal_tail_shared_convergence",
        "output_json": (
            ".tmp/hexrays_structuring_lab/cfg_validation/"
            "terminal_tail_shared_convergence.json"
        ),
        "expected": {
            "accepted_maturity": EXPECTED_MATURITY,
            "block_count": f"== {TERMINAL_TAIL_SHARED_EXPECTED_BLOCK_COUNT}",
            "byte_emit_count": "== 7",
            "shared_convergence_blocks": "== 1",
            "shared_convergence_predicate": "npred >= 6",
            "shared_guard_relative_start_ea": (
                TERMINAL_TAIL_SHARED_GUARD_RELATIVE_START
            ),
            "byte_emit_relative_start_eas": (
                TERMINAL_TAIL_SHARED_BYTE_EMIT_RELATIVE_STARTS
            ),
            "return_epilogue_relative_start_ea": (
                TERMINAL_TAIL_SHARED_RETURN_EPILOGUE_RELATIVE_START
            ),
            "edge_predicates": [
                "byte emit blocks appear for base+0 through base+6",
                "byte emit blocks base+0 through base+6 all flow to the same shared guard/convergence block",
                "the shared convergence block contains the early-return test and stage dispatch",
                "the shared convergence block can continue to the next byte stage",
                "the terminal return is reached through the same shared convergence corridor",
            ],
        },
    },
    "terminal_tail_split_guard": {
        "function": "hexrays_lab_terminal_tail_split_guard",
        "output_json": (
            ".tmp/hexrays_structuring_lab/cfg_validation/"
            "terminal_tail_split_guard.json"
        ),
        "expected": {
            "accepted_maturity": EXPECTED_MATURITY,
            "block_count": f"== {TERMINAL_TAIL_SPLIT_EXPECTED_BLOCK_COUNT}",
            "byte_emit_count": "== 7",
            "split_guard_count": "== 6",
            "terminal_region": "acyclic",
            "largest_scc_size": "== 1",
            "guard_relative_start_eas": (
                TERMINAL_TAIL_SPLIT_GUARD_RELATIVE_STARTS
            ),
            "early_return_relative_start_eas": (
                TERMINAL_TAIL_SPLIT_RETURN_RELATIVE_STARTS
            ),
            "continue_relative_start_eas": (
                TERMINAL_TAIL_SPLIT_CONTINUE_RELATIVE_STARTS
            ),
            "final_emit_relative_start_ea": (
                TERMINAL_TAIL_SPLIT_FINAL_EMIT_RELATIVE_START
            ),
            "return_epilogue_relative_start_ea": (
                TERMINAL_TAIL_SPLIT_RETURN_EPILOGUE_RELATIVE_START
            ),
            "edge_predicates": [
                "source-level emit/check split is fused by LOCOPT into six BLT_2WAY emit+guard blocks",
                "each fused emit+guard block has a return arm and a continue arm",
                "each continue arm from check[k] reaches byte[k + 1]",
                "no guard block is shared by multiple byte emit blocks",
                "byte6 reaches the terminal return path",
            ],
        },
    },
    "terminal_tail_unique_continuation": {
        "function": "hexrays_lab_terminal_tail_unique_continuation",
        "output_json": (
            ".tmp/hexrays_structuring_lab/cfg_validation/"
            "terminal_tail_unique_continuation.json"
        ),
        "expected": {
            "accepted_maturity": EXPECTED_MATURITY,
            "block_count": f"== {TERMINAL_TAIL_UNIQUE_EXPECTED_BLOCK_COUNT}",
            "byte_emit_count": "== 7",
            "unique_continuation_count": "== 7",
            "shared_convergence_blocks": "== 1",
            "shared_guard_relative_start_ea": (
                TERMINAL_TAIL_UNIQUE_GUARD_RELATIVE_START
            ),
            "byte_emit_relative_start_eas": (
                TERMINAL_TAIL_UNIQUE_BYTE_EMIT_RELATIVE_STARTS
            ),
            "return_epilogue_relative_start_ea": (
                TERMINAL_TAIL_UNIQUE_RETURN_EPILOGUE_RELATIVE_START
            ),
            "edge_predicates": [
                "byte emit blocks appear for base+0 through base+6",
                "source-level unique continuations are folded into byte emit bodies by LOCOPT",
                "each byte emit/continuation body reaches the same shared guard/convergence block",
                "the shared guard performs early-return testing and stage dispatch",
            ],
        },
    },
}

CASE_DEFAULTS = {
    "single_pred_chain_merge": {
        "function": DEFAULT_FUNCTION,
        "output_json": DEFAULT_OUTPUT_JSON,
    },
    "multi_pred_boundary_barrier": {
        "function": MULTI_PRED_FUNCTION,
        "output_json": MULTI_PRED_OUTPUT_JSON,
    },
    "side_effect_boundary_anchor": {
        "function": SIDE_EFFECT_FUNCTION,
        "output_json": SIDE_EFFECT_OUTPUT_JSON,
    },
    "clean_conditional_fork": {
        "function": CLEAN_FORK_FUNCTION,
        "output_json": CLEAN_FORK_OUTPUT_JSON,
    },
    "conditional_shell_boundary": {
        "function": CONDITIONAL_SHELL_FUNCTION,
        "output_json": CONDITIONAL_SHELL_OUTPUT_JSON,
    },
}
CASE_DEFAULTS.update({
    case_id: {
        "function": case["function"],
        "output_json": case["output_json"],
    }
    for case_id, case in BADWHILE_TRIANGLE_CASES.items()
})
CASE_DEFAULTS.update({
    case_id: {
        "function": case["function"],
        "output_json": case["output_json"],
    }
    for case_id, case in TERMINAL_TAIL_CASES.items()
})


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _hex_ea(value: int | None) -> str | None:
    if value is None:
        return None
    if value < 0:
        return None
    return f"0x{value:x}"


def _block_type_name(ida_hexrays, block_type: int) -> str:
    names = {
        ida_hexrays.BLT_NONE: "BLT_NONE",
        ida_hexrays.BLT_STOP: "BLT_STOP",
        ida_hexrays.BLT_0WAY: "BLT_0WAY",
        ida_hexrays.BLT_1WAY: "BLT_1WAY",
        ida_hexrays.BLT_2WAY: "BLT_2WAY",
        ida_hexrays.BLT_NWAY: "BLT_NWAY",
        ida_hexrays.BLT_XTRN: "BLT_XTRN",
    }
    return names.get(block_type, f"BLT_{block_type}")


def _instruction_opcodes(blk) -> list[int]:
    opcodes = []
    ins = blk.head
    while ins is not None:
        opcodes.append(int(ins.opcode))
        ins = ins.next
    return opcodes


def _opcode_names(opcodes: list[int]) -> list[str]:
    return [f"op_{opcode}" for opcode in opcodes]


def _call_target_from_dstr(dstr: str) -> str | None:
    match = re.search(r"\bcall\s+\$([A-Za-z_][A-Za-z0-9_@$?]*)", dstr)
    return match.group(1) if match else None


def _name_ea(name: str | None) -> str | None:
    if not name:
        return None
    try:
        import ida_name
        import idaapi
    except ImportError:
        return None
    ea = ida_name.get_name_ea(idaapi.BADADDR, name)
    if ea == idaapi.BADADDR:
        return None
    return _hex_ea(int(ea))


def _required_name_ea(name: str) -> str:
    ea = _name_ea(name)
    assert ea is not None, f"failed to resolve required symbol: {name}"
    return ea


def _instruction_records(blk) -> list[dict[str, object]]:
    records = []
    ins = blk.head
    while ins is not None:
        opcode = int(ins.opcode)
        dstr = str(ins.dstr())
        call_target_name = _call_target_from_dstr(dstr)
        records.append({
            "ea": _hex_ea(int(ins.ea)),
            "opcode": opcode,
            "opcode_name": f"op_{opcode}",
            "dstr": dstr,
            "call_target_name": call_target_name,
            "call_target_ea": _name_ea(call_target_name),
        })
        ins = ins.next
    return records


def _block_record(ida_hexrays, blk) -> dict[str, object]:
    instruction_opcodes = _instruction_opcodes(blk)
    instruction_records = _instruction_records(blk)
    return {
        "serial": int(blk.serial),
        "type": _block_type_name(ida_hexrays, int(blk.type)),
        "type_id": int(blk.type),
        "npred": int(blk.npred()),
        "nsucc": int(blk.nsucc()),
        "preds": [int(blk.pred(i)) for i in range(blk.npred())],
        "succs": [int(blk.succ(i)) for i in range(blk.nsucc())],
        "start_ea": _hex_ea(int(blk.start)),
        "end_ea": _hex_ea(int(blk.end)),
        "head_ea": _hex_ea(int(blk.head.ea)) if blk.head is not None else None,
        "tail_ea": _hex_ea(int(blk.tail.ea)) if blk.tail is not None else None,
        "tail_opcode": int(blk.tail.opcode) if blk.tail is not None else None,
        "tail_opcode_name": (
            f"op_{int(blk.tail.opcode)}" if blk.tail is not None else None
        ),
        "instruction_count": len(instruction_opcodes),
        "instruction_opcodes": instruction_opcodes,
        "instruction_opcode_names": _opcode_names(instruction_opcodes),
        "instructions": instruction_records,
        "call_targets": [
            {
                "name": record["call_target_name"],
                "ea": record["call_target_ea"],
            }
            for record in instruction_records
            if record["call_target_name"] is not None
        ],
    }


def _find_single_pred_chains(ida_hexrays, mba) -> list[list[int]]:
    chains = []
    for index in range(mba.qty):
        blk = mba.get_mblock(index)
        if blk is None:
            continue
        if int(blk.type) != int(ida_hexrays.BLT_1WAY):
            continue
        if blk.nsucc() != 1:
            continue

        chain = [int(blk.serial)]
        seen = {int(blk.serial)}
        current = blk
        while current.nsucc() == 1:
            next_serial = int(current.succ(0))
            if next_serial in seen:
                break
            if next_serial < 0 or next_serial >= mba.qty:
                break
            next_blk = mba.get_mblock(next_serial)
            if next_blk is None:
                break
            if next_blk.npred() != 1:
                break
            chain.append(next_serial)
            seen.add(next_serial)
            if int(next_blk.type) != int(ida_hexrays.BLT_1WAY):
                break
            current = next_blk

        if len(chain) >= 2:
            chains.append(chain)
    return chains


def _relative_ea(value: str | None, func_ea: int) -> str | None:
    if value is None:
        return None
    if not value.startswith("0x"):
        return None
    parsed = int(value, 16)
    if parsed < func_ea:
        return None
    return f"0x{parsed - func_ea:x}"


def _chain_signature(
    ida_hexrays,
    mba,
    chain: list[int],
    *,
    func_ea: int,
) -> dict[str, object]:
    blocks = [
        _block_record(ida_hexrays, mba.get_mblock(serial))
        for serial in chain
    ]
    body_blocks = [
        block for block in blocks
        if block["instruction_count"] != 0
    ]
    return {
        "serials": chain,
        "chain_length": len(chain),
        "chain_types": [block["type"] for block in blocks],
        "relative_start_eas": [
            _relative_ea(block["start_ea"], func_ea) for block in blocks
        ],
        "relative_end_eas": [
            _relative_ea(block["end_ea"], func_ea) for block in blocks
        ],
        "body_relative_start_eas": [
            _relative_ea(block["start_ea"], func_ea) for block in body_blocks
        ],
        "body_opcode_signatures": [
            block["instruction_opcodes"] for block in body_blocks
        ],
        "body_tail_opcodes": [block["tail_opcode"] for block in body_blocks],
        "blocks": blocks,
    }


def _matches_single_pred_chain_fixture(
    signature: dict[str, object],
    *,
    block_count: int,
    maturity_name: str,
) -> bool:
    return (
        maturity_name == EXPECTED_MATURITY
        and block_count == EXPECTED_BLOCK_COUNT
        and signature["chain_length"] == EXPECTED_CHAIN_LENGTH
        and signature["chain_types"] == EXPECTED_CHAIN_TYPES
        and signature["body_relative_start_eas"] == EXPECTED_BODY_RELATIVE_STARTS
        and signature["body_opcode_signatures"] == EXPECTED_BODY_OPCODE_SIGNATURES
        and signature["body_tail_opcodes"] == [55, 55, 55, 55]
    )


def _boundary_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
    boundary_relative_start: str,
) -> dict[str, object] | None:
    body_blocks = [
        block for block in blocks
        if block["instruction_count"] != 0
    ]
    blocks_by_serial = {
        int(block["serial"]): block for block in blocks
    }
    body_by_relative_start = {
        _relative_ea(block["start_ea"], func_ea): block
        for block in body_blocks
    }
    boundary = body_by_relative_start.get(boundary_relative_start)
    if boundary is None:
        return None

    pred_serials = [int(serial) for serial in boundary["preds"]]
    succ_serials = [int(serial) for serial in boundary["succs"]]
    pred_blocks = [
        blocks_by_serial[serial]
        for serial in pred_serials
        if serial in blocks_by_serial
    ]
    succ_blocks = [
        blocks_by_serial[serial]
        for serial in succ_serials
        if serial in blocks_by_serial
    ]
    return {
        "boundary_serial": boundary["serial"],
        "boundary_relative_start_ea": boundary_relative_start,
        "boundary": boundary,
        "boundary_pred_serials": pred_serials,
        "boundary_succ_serials": succ_serials,
        "boundary_pred_relative_start_eas": [
            _relative_ea(block["start_ea"], func_ea)
            for block in pred_blocks
        ],
        "boundary_succ_relative_start_eas": [
            _relative_ea(block["start_ea"], func_ea)
            for block in succ_blocks
        ],
        "body_relative_start_eas": [
            _relative_ea(block["start_ea"], func_ea)
            for block in body_blocks
        ],
        "body_opcode_signatures_by_relative_start": {
            str(_relative_ea(block["start_ea"], func_ea)): block[
                "instruction_opcodes"
            ]
            for block in body_blocks
        },
        "body_opcode_names_by_relative_start": {
            str(_relative_ea(block["start_ea"], func_ea)): block[
                "instruction_opcode_names"
            ]
            for block in body_blocks
        },
        "blocks": blocks,
    }


def _multi_pred_boundary_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
) -> dict[str, object] | None:
    return _boundary_signature(
        blocks,
        func_ea=func_ea,
        boundary_relative_start=MULTI_PRED_BOUNDARY_RELATIVE_START,
    )


def _side_effect_boundary_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
) -> dict[str, object] | None:
    return _boundary_signature(
        blocks,
        func_ea=func_ea,
        boundary_relative_start=SIDE_EFFECT_BOUNDARY_RELATIVE_START,
    )


def _clean_fork_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
) -> dict[str, object] | None:
    signature = _boundary_signature(
        blocks,
        func_ea=func_ea,
        boundary_relative_start=CLEAN_FORK_JOIN_RELATIVE_START,
    )
    if signature is None:
        return None

    body_blocks = [
        block for block in blocks
        if block["instruction_count"] != 0
    ]
    blocks_by_serial = {
        int(block["serial"]): block for block in blocks
    }
    body_by_relative_start = {
        _relative_ea(block["start_ea"], func_ea): block
        for block in body_blocks
    }
    entry = body_by_relative_start.get(CLEAN_FORK_ENTRY_RELATIVE_START)
    if entry is None:
        return None

    entry_succ_blocks = [
        blocks_by_serial[serial]
        for serial in [int(serial) for serial in entry["succs"]]
        if serial in blocks_by_serial
    ]
    arm_paths = []
    for succ_block in entry_succ_blocks:
        path = [_relative_ea(succ_block["start_ea"], func_ea)]
        if succ_block["nsucc"] == 1:
            arm_serial = int(succ_block["succs"][0])
            arm_block = blocks_by_serial.get(arm_serial)
            if arm_block is not None:
                path.append(_relative_ea(arm_block["start_ea"], func_ea))
                if arm_block["nsucc"] == 1:
                    join_serial = int(arm_block["succs"][0])
                    join_block = blocks_by_serial.get(join_serial)
                    if join_block is not None:
                        path.append(_relative_ea(
                            join_block["start_ea"],
                            func_ea,
                        ))
        arm_paths.append(path)
    signature["entry_serial"] = entry["serial"]
    signature["entry_relative_start_ea"] = CLEAN_FORK_ENTRY_RELATIVE_START
    signature["entry"] = entry
    signature["entry_succ_relative_start_eas"] = [
        _relative_ea(block["start_ea"], func_ea)
        for block in entry_succ_blocks
    ]
    signature["arm_paths_relative_start_eas"] = arm_paths
    return signature


def _successor_path_relative_starts(
    *,
    blocks_by_serial: dict[int, dict[str, object]],
    start_block: dict[str, object],
    func_ea: int,
    max_steps: int = 3,
    stop_relative_start: str | None = None,
) -> list[str | None]:
    path = [_relative_ea(start_block["start_ea"], func_ea)]
    current = start_block
    for _step in range(max_steps - 1):
        if current["nsucc"] != 1:
            break
        next_serial = int(current["succs"][0])
        next_block = blocks_by_serial.get(next_serial)
        if next_block is None:
            break
        relative_start = _relative_ea(next_block["start_ea"], func_ea)
        path.append(relative_start)
        if relative_start == stop_relative_start:
            break
        current = next_block
    return path


def _conditional_shell_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
) -> dict[str, object] | None:
    signature = _boundary_signature(
        blocks,
        func_ea=func_ea,
        boundary_relative_start=CONDITIONAL_SHELL_BOUNDARY_RELATIVE_START,
    )
    if signature is None:
        return None

    body_blocks = [
        block for block in blocks
        if block["instruction_count"] != 0
    ]
    blocks_by_serial = {
        int(block["serial"]): block for block in blocks
    }
    body_by_relative_start = {
        _relative_ea(block["start_ea"], func_ea): block
        for block in body_blocks
    }
    entry = body_by_relative_start.get(CONDITIONAL_SHELL_ENTRY_RELATIVE_START)
    shell = body_by_relative_start.get(CONDITIONAL_SHELL_RELATIVE_START)
    if entry is None or shell is None:
        return None

    entry_succ_blocks = [
        blocks_by_serial[serial]
        for serial in [int(serial) for serial in entry["succs"]]
        if serial in blocks_by_serial
    ]
    shell_pred_blocks = [
        blocks_by_serial[serial]
        for serial in [int(serial) for serial in shell["preds"]]
        if serial in blocks_by_serial
    ]
    shell_succ_blocks = [
        blocks_by_serial[serial]
        for serial in [int(serial) for serial in shell["succs"]]
        if serial in blocks_by_serial
    ]
    signature["entry_serial"] = entry["serial"]
    signature["entry_relative_start_ea"] = CONDITIONAL_SHELL_ENTRY_RELATIVE_START
    signature["entry"] = entry
    signature["entry_succ_relative_start_eas"] = [
        _relative_ea(block["start_ea"], func_ea)
        for block in entry_succ_blocks
    ]
    signature["entry_to_shell_paths_relative_start_eas"] = [
        _successor_path_relative_starts(
            blocks_by_serial=blocks_by_serial,
            start_block=block,
            func_ea=func_ea,
            stop_relative_start=CONDITIONAL_SHELL_RELATIVE_START,
        )
        for block in entry_succ_blocks
    ]
    signature["shell_serial"] = shell["serial"]
    signature["shell_relative_start_ea"] = CONDITIONAL_SHELL_RELATIVE_START
    signature["shell"] = shell
    signature["shell_pred_relative_start_eas"] = [
        _relative_ea(block["start_ea"], func_ea)
        for block in shell_pred_blocks
    ]
    signature["shell_succ_relative_start_eas"] = [
        _relative_ea(block["start_ea"], func_ea)
        for block in shell_succ_blocks
    ]
    signature["shell_arm_paths_relative_start_eas"] = [
        _successor_path_relative_starts(
            blocks_by_serial=blocks_by_serial,
            start_block=block,
            func_ea=func_ea,
            stop_relative_start=CONDITIONAL_SHELL_BOUNDARY_RELATIVE_START,
        )
        for block in shell_succ_blocks
    ]
    return signature


def _blocks_by_serial(
    blocks: list[dict[str, object]],
) -> dict[int, dict[str, object]]:
    return {
        int(block["serial"]): block for block in blocks
    }


def _successor_blocks(
    block: dict[str, object],
    blocks_by_serial: dict[int, dict[str, object]],
) -> list[dict[str, object]]:
    return [
        blocks_by_serial[int(serial)]
        for serial in block["succs"]
        if int(serial) in blocks_by_serial
    ]


def _predecessor_blocks(
    block: dict[str, object],
    blocks_by_serial: dict[int, dict[str, object]],
) -> list[dict[str, object]]:
    return [
        blocks_by_serial[int(serial)]
        for serial in block["preds"]
        if int(serial) in blocks_by_serial
    ]


def _has_successor(
    block: dict[str, object],
    target: dict[str, object],
) -> bool:
    return int(target["serial"]) in [int(serial) for serial in block["succs"]]


def _is_conditional_case_block(block: dict[str, object]) -> bool:
    return block["type"] == "BLT_2WAY" and block["nsucc"] == 2


def _is_minimal_goto_like_one_way(block: dict[str, object]) -> bool:
    return (
        block["type"] == "BLT_1WAY"
        and block["nsucc"] == 1
        and not block["call_targets"]
        and (
            block["instruction_count"] == 0
            or block["instruction_opcodes"] in ([], [55])
        )
    )


def _relative_start_list(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
) -> list[str | None]:
    return [
        _relative_ea(block["start_ea"], func_ea)
        for block in blocks
    ]


def _badwhile_role_fields(
    role: str,
    block: dict[str, object],
    *,
    blocks_by_serial: dict[int, dict[str, object]],
    func_ea: int,
) -> dict[str, object]:
    pred_blocks = _predecessor_blocks(block, blocks_by_serial)
    succ_blocks = _successor_blocks(block, blocks_by_serial)
    return {
        role: block,
        f"{role}_serial": block["serial"],
        f"{role}_relative_start_ea": _relative_ea(
            block["start_ea"],
            func_ea,
        ),
        f"{role}_pred_relative_start_eas": _relative_start_list(
            pred_blocks,
            func_ea=func_ea,
        ),
        f"{role}_succ_relative_start_eas": _relative_start_list(
            succ_blocks,
            func_ea=func_ea,
        ),
    }


def _badwhile_base_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
    variant: str,
    roles: dict[str, dict[str, object]],
) -> dict[str, object]:
    blocks_by_serial = _blocks_by_serial(blocks)
    body_blocks = [
        block for block in blocks
        if block["instruction_count"] != 0
    ]
    signature: dict[str, object] = {
        "variant": variant,
        "block_count": len(blocks),
        "body_relative_start_eas": _relative_start_list(
            body_blocks,
            func_ea=func_ea,
        ),
        "body_opcode_signatures_by_relative_start": {
            str(_relative_ea(block["start_ea"], func_ea)): block[
                "instruction_opcodes"
            ]
            for block in body_blocks
        },
        "body_opcode_names_by_relative_start": {
            str(_relative_ea(block["start_ea"], func_ea)): block[
                "instruction_opcode_names"
            ]
            for block in body_blocks
        },
        "blocks": blocks,
    }
    for role, block in roles.items():
        signature.update(_badwhile_role_fields(
            role,
            block,
            blocks_by_serial=blocks_by_serial,
            func_ea=func_ea,
        ))
    return signature


def _one_way_intermediates_between(
    source: dict[str, object],
    target: dict[str, object],
    *,
    blocks_by_serial: dict[int, dict[str, object]],
    func_ea: int,
) -> list[dict[str, object]]:
    target_serial = int(target["serial"])
    intermediates = []
    for succ in _successor_blocks(source, blocks_by_serial):
        if int(succ["serial"]) == target_serial:
            continue
        if (
            succ["type"] == "BLT_1WAY"
            and succ["nsucc"] == 1
            and int(succ["succs"][0]) == target_serial
        ):
            intermediates.append({
                "serial": succ["serial"],
                "relative_start_ea": _relative_ea(
                    succ["start_ea"],
                    func_ea,
                ),
                "instruction_opcodes": succ["instruction_opcodes"],
            })
    return intermediates


def _badwhile_direct_triangle_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
) -> dict[str, object] | None:
    blocks_by_serial = _blocks_by_serial(blocks)
    for case_cond in blocks:
        if not _is_conditional_case_block(case_cond):
            continue
        case_pred_blocks = _predecessor_blocks(case_cond, blocks_by_serial)
        for father in case_pred_blocks:
            if (
                father["type"] != "BLT_2WAY"
                or father["nsucc"] != 2
                or not _has_successor(father, case_cond)
            ):
                continue
            for dispatcher in _successor_blocks(father, blocks_by_serial):
                if int(dispatcher["serial"]) == int(case_cond["serial"]):
                    continue
                if (
                    dispatcher["type"] != "BLT_2WAY"
                    or dispatcher["nsucc"] != 2
                    or not _has_successor(dispatcher, case_cond)
                    or int(dispatcher["serial"]) not in case_cond["preds"]
                ):
                    continue
                if sorted(int(serial) for serial in case_cond["preds"]) != sorted([
                    int(father["serial"]),
                    int(dispatcher["serial"]),
                ]):
                    continue
                signature = _badwhile_base_signature(
                    blocks,
                    func_ea=func_ea,
                    variant="direct",
                    roles={
                        "father": father,
                        "dispatcher": dispatcher,
                        "case_cond": case_cond,
                    },
                )
                signature["father_to_case_intermediate_one_way_blocks"] = (
                    _one_way_intermediates_between(
                        father,
                        case_cond,
                        blocks_by_serial=blocks_by_serial,
                        func_ea=func_ea,
                    )
                )
                return signature
    return None


def _badwhile_trampoline_triangle_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
) -> dict[str, object] | None:
    blocks_by_serial = _blocks_by_serial(blocks)
    for case_cond in blocks:
        if not _is_conditional_case_block(case_cond):
            continue
        case_pred_blocks = _predecessor_blocks(case_cond, blocks_by_serial)
        for trampoline in case_pred_blocks:
            if (
                not _is_minimal_goto_like_one_way(trampoline)
                or not _has_successor(trampoline, case_cond)
            ):
                continue
            trampoline_pred_blocks = _predecessor_blocks(
                trampoline,
                blocks_by_serial,
            )
            if len(trampoline_pred_blocks) != 1:
                continue
            father = trampoline_pred_blocks[0]
            if (
                father["type"] != "BLT_2WAY"
                or father["nsucc"] != 2
                or int(father["serial"]) in case_cond["preds"]
                or not _has_successor(father, trampoline)
            ):
                continue
            for dispatcher in case_pred_blocks:
                if int(dispatcher["serial"]) == int(trampoline["serial"]):
                    continue
                if (
                    dispatcher["type"] != "BLT_2WAY"
                    or dispatcher["nsucc"] != 2
                    or not _has_successor(father, dispatcher)
                    or not _has_successor(dispatcher, case_cond)
                ):
                    continue
                if sorted(int(serial) for serial in case_cond["preds"]) != sorted([
                    int(trampoline["serial"]),
                    int(dispatcher["serial"]),
                ]):
                    continue
                signature = _badwhile_base_signature(
                    blocks,
                    func_ea=func_ea,
                    variant="trampoline",
                    roles={
                        "father": father,
                        "trampoline": trampoline,
                        "dispatcher": dispatcher,
                        "case_cond": case_cond,
                    },
                )
                signature["case_cond_has_father_direct_pred"] = (
                    int(father["serial"]) in case_cond["preds"]
                )
                signature["trampoline_is_minimal_goto_like"] = (
                    _is_minimal_goto_like_one_way(trampoline)
                )
                return signature
    return None


def _badwhile_duplicate_group_triangle_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
) -> dict[str, object] | None:
    blocks_by_serial = _blocks_by_serial(blocks)
    for case_cond in blocks:
        if not _is_conditional_case_block(case_cond):
            continue
        case_pred_blocks = _predecessor_blocks(case_cond, blocks_by_serial)
        for dispatcher in case_pred_blocks:
            if (
                dispatcher["type"] != "BLT_2WAY"
                or dispatcher["nsucc"] != 2
                or not _has_successor(dispatcher, case_cond)
            ):
                continue
            for shared in _predecessor_blocks(dispatcher, blocks_by_serial):
                if (
                    shared["type"] != "BLT_1WAY"
                    or shared["npred"] != 2
                    or shared["nsucc"] != 1
                    or not _has_successor(shared, dispatcher)
                ):
                    continue
                pred_blocks = _predecessor_blocks(shared, blocks_by_serial)
                if len(pred_blocks) != 2:
                    continue
                if not all(
                    pred["type"] == "BLT_2WAY"
                    and pred["nsucc"] == 2
                    and _has_successor(pred, shared)
                    and _has_successor(pred, case_cond)
                    for pred in pred_blocks
                ):
                    continue
                expected_case_preds = sorted(
                    [int(dispatcher["serial"])]
                    + [int(pred["serial"]) for pred in pred_blocks]
                )
                if (
                    sorted(int(serial) for serial in case_cond["preds"])
                    != expected_case_preds
                ):
                    continue
                pred_blocks = sorted(
                    pred_blocks,
                    key=lambda block: int(block["serial"]),
                )
                signature = _badwhile_base_signature(
                    blocks,
                    func_ea=func_ea,
                    variant="duplicate_group",
                    roles={
                        "pred_a": pred_blocks[0],
                        "pred_b": pred_blocks[1],
                        "shared": shared,
                        "dispatcher": dispatcher,
                        "case_cond": case_cond,
                    },
                )
                signature["duplicate_pred_relative_start_eas"] = [
                    signature["pred_a_relative_start_ea"],
                    signature["pred_b_relative_start_ea"],
                ]
                return signature
    return None


def _badwhile_triangle_signature(
    case_id: str,
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
) -> dict[str, object] | None:
    variant = BADWHILE_TRIANGLE_CASES[case_id]["variant"]
    if variant == "direct":
        return _badwhile_direct_triangle_signature(blocks, func_ea=func_ea)
    if variant == "trampoline":
        return _badwhile_trampoline_triangle_signature(blocks, func_ea=func_ea)
    if variant == "duplicate_group":
        return _badwhile_duplicate_group_triangle_signature(
            blocks,
            func_ea=func_ea,
        )
    raise AssertionError(f"unknown bogus-loop triangle variant: {variant}")


def _terminal_tail_candidate_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
) -> dict[str, object]:
    """Collect raw terminal-tail block evidence before exact validators exist."""
    body_blocks = [
        block for block in blocks
        if block["instruction_count"] != 0
    ]
    return {
        "relative_start_eas": [
            _relative_ea(block["start_ea"], func_ea)
            for block in body_blocks
        ],
        "block_count": len(blocks),
        "body_block_count": len(body_blocks),
        "body_opcode_signatures_by_relative_start": {
            str(_relative_ea(block["start_ea"], func_ea)): block[
                "instruction_opcodes"
            ]
            for block in body_blocks
        },
        "body_opcode_names_by_relative_start": {
            str(_relative_ea(block["start_ea"], func_ea)): block[
                "instruction_opcode_names"
            ]
            for block in body_blocks
        },
        "blocks": blocks,
        "validator_status": "planned_exact_matcher_not_implemented",
    }


def _terminal_tail_ref_cascade_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
) -> dict[str, object] | None:
    return _terminal_tail_linear_cascade_signature(
        blocks,
        func_ea=func_ea,
        guard_relative_starts=TERMINAL_TAIL_REF_GUARD_RELATIVE_STARTS,
        return_relative_starts=TERMINAL_TAIL_REF_RETURN_RELATIVE_STARTS,
        continue_relative_starts=TERMINAL_TAIL_REF_CONTINUE_RELATIVE_STARTS,
        final_emit_relative_start=TERMINAL_TAIL_REF_FINAL_EMIT_RELATIVE_START,
        return_epilogue_relative_start=(
            TERMINAL_TAIL_REF_RETURN_EPILOGUE_RELATIVE_START
        ),
    )


def _terminal_tail_split_guard_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
) -> dict[str, object] | None:
    return _terminal_tail_linear_cascade_signature(
        blocks,
        func_ea=func_ea,
        guard_relative_starts=TERMINAL_TAIL_SPLIT_GUARD_RELATIVE_STARTS,
        return_relative_starts=TERMINAL_TAIL_SPLIT_RETURN_RELATIVE_STARTS,
        continue_relative_starts=TERMINAL_TAIL_SPLIT_CONTINUE_RELATIVE_STARTS,
        final_emit_relative_start=TERMINAL_TAIL_SPLIT_FINAL_EMIT_RELATIVE_START,
        return_epilogue_relative_start=(
            TERMINAL_TAIL_SPLIT_RETURN_EPILOGUE_RELATIVE_START
        ),
    )


def _terminal_tail_linear_cascade_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
    guard_relative_starts: list[str],
    return_relative_starts: list[str],
    continue_relative_starts: list[str],
    final_emit_relative_start: str,
    return_epilogue_relative_start: str,
) -> dict[str, object] | None:
    signature = _terminal_tail_candidate_signature(blocks, func_ea=func_ea)
    blocks_by_serial = {
        int(block["serial"]): block for block in blocks
    }
    body_blocks = [
        block for block in blocks
        if block["instruction_count"] != 0
    ]
    body_by_relative_start = {
        _relative_ea(block["start_ea"], func_ea): block
        for block in body_blocks
    }
    guard_blocks = [
        body_by_relative_start.get(relative_start)
        for relative_start in guard_relative_starts
    ]
    return_blocks = [
        body_by_relative_start.get(relative_start)
        for relative_start in return_relative_starts
    ]
    continue_blocks = [
        block
        for block in blocks
        if _relative_ea(block["start_ea"], func_ea)
        in continue_relative_starts
    ]
    final_emit = body_by_relative_start.get(final_emit_relative_start)
    return_epilogue = body_by_relative_start.get(return_epilogue_relative_start)
    if (
        any(block is None for block in guard_blocks)
        or any(block is None for block in return_blocks)
        or len(continue_blocks) != len(TERMINAL_TAIL_REF_CONTINUE_RELATIVE_STARTS)
        or final_emit is None
        or return_epilogue is None
    ):
        return None

    guard_paths = []
    for index, guard in enumerate(guard_blocks):
        assert isinstance(guard, dict)
        return_block = return_blocks[index]
        assert isinstance(return_block, dict)
        return_serial = int(return_block["serial"])
        continue_serials = [
            int(serial)
            for serial in guard["succs"]
            if int(serial) != return_serial
        ]
        continue_path = []
        if len(continue_serials) == 1:
            continue_block = blocks_by_serial.get(continue_serials[0])
            if continue_block is not None:
                continue_path.append(
                    _relative_ea(continue_block["start_ea"], func_ea)
                )
                if continue_block["nsucc"] == 1:
                    next_block = blocks_by_serial.get(
                        int(continue_block["succs"][0])
                    )
                    if next_block is not None:
                        continue_path.append(
                            _relative_ea(next_block["start_ea"], func_ea)
                        )
        guard_paths.append({
            "guard_relative_start_ea": _relative_ea(
                guard["start_ea"],
                func_ea,
            ),
            "return_relative_start_ea": _relative_ea(
                return_block["start_ea"],
                func_ea,
            ),
            "continue_path_relative_start_eas": continue_path,
        })

    signature.update({
        "validator_status": "exact_matcher_available",
        "guards": guard_blocks,
        "early_returns": return_blocks,
        "continue_handoffs": continue_blocks,
        "final_emit": final_emit,
        "return_epilogue": return_epilogue,
        "guard_paths": guard_paths,
        "return_epilogue_pred_relative_start_eas": [
            _relative_ea(blocks_by_serial[int(serial)]["start_ea"], func_ea)
            for serial in return_epilogue["preds"]
            if int(serial) in blocks_by_serial
        ],
    })
    return signature


def _matches_terminal_tail_ref_cascade_fixture(
    signature: dict[str, object] | None,
    *,
    block_count: int,
    maturity_name: str,
) -> bool:
    return _matches_terminal_tail_linear_cascade_fixture(
        signature,
        block_count=block_count,
        maturity_name=maturity_name,
        expected_block_count=TERMINAL_TAIL_REF_EXPECTED_BLOCK_COUNT,
        continue_relative_starts=TERMINAL_TAIL_REF_CONTINUE_RELATIVE_STARTS,
        guard_relative_starts=TERMINAL_TAIL_REF_GUARD_RELATIVE_STARTS,
        return_relative_starts=TERMINAL_TAIL_REF_RETURN_RELATIVE_STARTS,
        final_emit_relative_start=TERMINAL_TAIL_REF_FINAL_EMIT_RELATIVE_START,
    )


def _matches_terminal_tail_split_guard_fixture(
    signature: dict[str, object] | None,
    *,
    block_count: int,
    maturity_name: str,
) -> bool:
    return _matches_terminal_tail_linear_cascade_fixture(
        signature,
        block_count=block_count,
        maturity_name=maturity_name,
        expected_block_count=TERMINAL_TAIL_SPLIT_EXPECTED_BLOCK_COUNT,
        continue_relative_starts=TERMINAL_TAIL_SPLIT_CONTINUE_RELATIVE_STARTS,
        guard_relative_starts=TERMINAL_TAIL_SPLIT_GUARD_RELATIVE_STARTS,
        return_relative_starts=TERMINAL_TAIL_SPLIT_RETURN_RELATIVE_STARTS,
        final_emit_relative_start=TERMINAL_TAIL_SPLIT_FINAL_EMIT_RELATIVE_START,
    )


def _matches_terminal_tail_linear_cascade_fixture(
    signature: dict[str, object] | None,
    *,
    block_count: int,
    maturity_name: str,
    expected_block_count: int,
    continue_relative_starts: list[str],
    guard_relative_starts: list[str],
    return_relative_starts: list[str],
    final_emit_relative_start: str,
) -> bool:
    if signature is None:
        return False
    guards = signature["guards"]
    early_returns = signature["early_returns"]
    continue_handoffs = signature["continue_handoffs"]
    final_emit = signature["final_emit"]
    return_epilogue = signature["return_epilogue"]
    guard_paths = signature["guard_paths"]
    assert isinstance(guards, list)
    assert isinstance(early_returns, list)
    assert isinstance(continue_handoffs, list)
    assert isinstance(final_emit, dict)
    assert isinstance(return_epilogue, dict)
    assert isinstance(guard_paths, list)

    expected_continue_paths = [
        [handoff, next_guard]
        for handoff, next_guard in zip(
            continue_relative_starts,
            guard_relative_starts[1:] + [final_emit_relative_start],
            strict=True,
        )
    ]
    return (
        maturity_name == EXPECTED_MATURITY
        and block_count == expected_block_count
        and len(guards) == 6
        and len(early_returns) == 6
        and len(continue_handoffs) == 6
        and [guard["type"] for guard in guards] == ["BLT_2WAY"] * 6
        and [guard["npred"] for guard in guards] == [1] * 6
        and [guard["nsucc"] for guard in guards] == [2] * 6
        and guards[0]["instruction_opcodes"]
        == TERMINAL_TAIL_REF_FIRST_GUARD_OPCODE_SIGNATURE
        and [
            guard["instruction_opcodes"]
            for guard in guards[1:]
        ] == [TERMINAL_TAIL_REF_GUARD_OPCODE_SIGNATURE] * 5
        and [
            block["instruction_opcodes"]
            for block in early_returns
        ] == [TERMINAL_TAIL_REF_RETURN_OPCODE_SIGNATURE] * 6
        and [
            block["instruction_count"]
            for block in continue_handoffs
        ] == [0] * 6
        and final_emit["type"] == "BLT_1WAY"
        and final_emit["instruction_opcodes"]
        == TERMINAL_TAIL_REF_FINAL_EMIT_OPCODE_SIGNATURE
        and return_epilogue["type"] == "BLT_1WAY"
        and return_epilogue["npred"] == 7
        and return_epilogue["instruction_opcodes"]
        == TERMINAL_TAIL_REF_RETURN_EPILOGUE_OPCODE_SIGNATURE
        and [
            path["continue_path_relative_start_eas"]
            for path in guard_paths
        ] == expected_continue_paths
        and sorted(signature["return_epilogue_pred_relative_start_eas"])
        == sorted(
            return_relative_starts
            + [final_emit_relative_start]
        )
    )


def _terminal_tail_shared_convergence_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
) -> dict[str, object] | None:
    return _terminal_tail_shared_guard_signature(
        blocks,
        func_ea=func_ea,
        shared_guard_relative_start=TERMINAL_TAIL_SHARED_GUARD_RELATIVE_START,
        byte_emit_relative_starts=(
            TERMINAL_TAIL_SHARED_BYTE_EMIT_RELATIVE_STARTS
        ),
        stage_assign_relative_starts=(
            TERMINAL_TAIL_SHARED_STAGE_ASSIGN_RELATIVE_STARTS
        ),
        early_return_relative_start=(
            TERMINAL_TAIL_SHARED_EARLY_RETURN_RELATIVE_START
        ),
        stage_dispatch_relative_start=TERMINAL_TAIL_SHARED_STAGE_DISPATCH_START,
        return_epilogue_relative_start=(
            TERMINAL_TAIL_SHARED_RETURN_EPILOGUE_RELATIVE_START
        ),
    )


def _terminal_tail_unique_continuation_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
) -> dict[str, object] | None:
    return _terminal_tail_shared_guard_signature(
        blocks,
        func_ea=func_ea,
        shared_guard_relative_start=TERMINAL_TAIL_UNIQUE_GUARD_RELATIVE_START,
        byte_emit_relative_starts=(
            TERMINAL_TAIL_UNIQUE_BYTE_EMIT_RELATIVE_STARTS
        ),
        stage_assign_relative_starts=(
            TERMINAL_TAIL_UNIQUE_STAGE_ASSIGN_RELATIVE_STARTS
        ),
        early_return_relative_start=(
            TERMINAL_TAIL_UNIQUE_EARLY_RETURN_RELATIVE_START
        ),
        stage_dispatch_relative_start=TERMINAL_TAIL_UNIQUE_STAGE_DISPATCH_START,
        return_epilogue_relative_start=(
            TERMINAL_TAIL_UNIQUE_RETURN_EPILOGUE_RELATIVE_START
        ),
    )


def _terminal_tail_shared_guard_signature(
    blocks: list[dict[str, object]],
    *,
    func_ea: int,
    shared_guard_relative_start: str,
    byte_emit_relative_starts: list[str],
    stage_assign_relative_starts: list[str],
    early_return_relative_start: str,
    stage_dispatch_relative_start: str,
    return_epilogue_relative_start: str,
) -> dict[str, object] | None:
    signature = _terminal_tail_candidate_signature(blocks, func_ea=func_ea)
    blocks_by_serial = {
        int(block["serial"]): block for block in blocks
    }
    body_blocks = [
        block for block in blocks
        if block["instruction_count"] != 0
    ]
    body_by_relative_start = {
        _relative_ea(block["start_ea"], func_ea): block
        for block in body_blocks
    }
    shared_guard = body_by_relative_start.get(
        shared_guard_relative_start
    )
    byte_emit_blocks = [
        body_by_relative_start.get(relative_start)
        for relative_start in byte_emit_relative_starts
    ]
    stage_assign_blocks = [
        body_by_relative_start.get(relative_start)
        for relative_start in stage_assign_relative_starts
    ]
    early_return = body_by_relative_start.get(
        early_return_relative_start
    )
    stage_dispatch = body_by_relative_start.get(
        stage_dispatch_relative_start
    )
    return_epilogue = body_by_relative_start.get(
        return_epilogue_relative_start
    )
    if (
        shared_guard is None
        or any(block is None for block in byte_emit_blocks)
        or any(block is None for block in stage_assign_blocks)
        or early_return is None
        or stage_dispatch is None
        or return_epilogue is None
    ):
        return None

    shared_pred_blocks = [
        blocks_by_serial[int(serial)]
        for serial in shared_guard["preds"]
        if int(serial) in blocks_by_serial
    ]
    shared_succ_blocks = [
        blocks_by_serial[int(serial)]
        for serial in shared_guard["succs"]
        if int(serial) in blocks_by_serial
    ]
    signature.update({
        "validator_status": "exact_matcher_available",
        "shared_guard": shared_guard,
        "byte_emits": byte_emit_blocks,
        "stage_assignments": stage_assign_blocks,
        "early_return": early_return,
        "stage_dispatch": stage_dispatch,
        "return_epilogue": return_epilogue,
        "shared_guard_pred_relative_start_eas": [
            _relative_ea(block["start_ea"], func_ea)
            for block in shared_pred_blocks
        ],
        "shared_guard_succ_relative_start_eas": [
            _relative_ea(block["start_ea"], func_ea)
            for block in shared_succ_blocks
        ],
    })
    return signature


def _matches_terminal_tail_shared_convergence_fixture(
    signature: dict[str, object] | None,
    *,
    block_count: int,
    maturity_name: str,
) -> bool:
    return _matches_terminal_tail_shared_guard_fixture(
        signature,
        block_count=block_count,
        maturity_name=maturity_name,
        expected_block_count=TERMINAL_TAIL_SHARED_EXPECTED_BLOCK_COUNT,
        byte_emit_relative_starts=TERMINAL_TAIL_SHARED_BYTE_EMIT_RELATIVE_STARTS,
        first_emit_opcode_signature=TERMINAL_TAIL_SHARED_BYTE_EMIT_OPCODE_SIGNATURE,
        middle_emit_opcode_signature=TERMINAL_TAIL_SHARED_BYTE_EMIT_OPCODE_SIGNATURE,
        final_emit_opcode_signature=TERMINAL_TAIL_SHARED_FINAL_EMIT_OPCODE_SIGNATURE,
    )


def _matches_terminal_tail_unique_continuation_fixture(
    signature: dict[str, object] | None,
    *,
    block_count: int,
    maturity_name: str,
) -> bool:
    return _matches_terminal_tail_shared_guard_fixture(
        signature,
        block_count=block_count,
        maturity_name=maturity_name,
        expected_block_count=TERMINAL_TAIL_UNIQUE_EXPECTED_BLOCK_COUNT,
        byte_emit_relative_starts=TERMINAL_TAIL_UNIQUE_BYTE_EMIT_RELATIVE_STARTS,
        first_emit_opcode_signature=(
            TERMINAL_TAIL_UNIQUE_FIRST_BYTE_EMIT_OPCODE_SIGNATURE
        ),
        middle_emit_opcode_signature=(
            TERMINAL_TAIL_UNIQUE_BYTE_EMIT_OPCODE_SIGNATURE
        ),
        final_emit_opcode_signature=(
            TERMINAL_TAIL_UNIQUE_FINAL_EMIT_OPCODE_SIGNATURE
        ),
    )


def _matches_terminal_tail_shared_guard_fixture(
    signature: dict[str, object] | None,
    *,
    block_count: int,
    maturity_name: str,
    expected_block_count: int,
    byte_emit_relative_starts: list[str],
    first_emit_opcode_signature: list[int],
    middle_emit_opcode_signature: list[int],
    final_emit_opcode_signature: list[int],
) -> bool:
    if signature is None:
        return False
    shared_guard = signature["shared_guard"]
    byte_emits = signature["byte_emits"]
    stage_assignments = signature["stage_assignments"]
    early_return = signature["early_return"]
    stage_dispatch = signature["stage_dispatch"]
    return_epilogue = signature["return_epilogue"]
    assert isinstance(shared_guard, dict)
    assert isinstance(byte_emits, list)
    assert isinstance(stage_assignments, list)
    assert isinstance(early_return, dict)
    assert isinstance(stage_dispatch, dict)
    assert isinstance(return_epilogue, dict)
    return (
        maturity_name == EXPECTED_MATURITY
        and block_count == expected_block_count
        and shared_guard["type"] == "BLT_2WAY"
        and shared_guard["npred"] == 7
        and shared_guard["nsucc"] == 2
        and shared_guard["instruction_opcodes"]
        == TERMINAL_TAIL_SHARED_GUARD_OPCODE_SIGNATURE
        and sorted(signature["shared_guard_pred_relative_start_eas"])
        == sorted(byte_emit_relative_starts)
        and len(byte_emits) == 7
        and byte_emits[0]["instruction_opcodes"] == first_emit_opcode_signature
        and [block["instruction_opcodes"] for block in byte_emits[1:-1]]
        == [middle_emit_opcode_signature] * 5
        and byte_emits[-1]["instruction_opcodes"]
        == final_emit_opcode_signature
        and [
            block["succs"][0]
            for block in byte_emits
        ] == [shared_guard["serial"]] * 7
        and len(stage_assignments) == 6
        and [block["type"] for block in stage_assignments] == ["BLT_1WAY"] * 6
        and early_return["succs"] == [return_epilogue["serial"]]
        and return_epilogue["npred"] == 2
    )


def _matches_multi_pred_boundary_fixture(
    signature: dict[str, object] | None,
    *,
    block_count: int,
    maturity_name: str,
) -> bool:
    if signature is None:
        return False
    boundary = signature["boundary"]
    assert isinstance(boundary, dict)
    body_opcodes = signature["body_opcode_signatures_by_relative_start"]
    assert isinstance(body_opcodes, dict)
    return (
        maturity_name == EXPECTED_MATURITY
        and block_count == MULTI_PRED_EXPECTED_BLOCK_COUNT
        and boundary["type"] == "BLT_1WAY"
        and boundary["npred"] == 2
        and boundary["nsucc"] == 1
        and boundary["instruction_opcodes"]
        == MULTI_PRED_BOUNDARY_OPCODE_SIGNATURE
        and sorted(signature["boundary_pred_relative_start_eas"])
        == MULTI_PRED_BOUNDARY_INCOMING_RELATIVE_STARTS
        and signature["boundary_succ_relative_start_eas"]
        == [MULTI_PRED_BOUNDARY_SUCCESSOR_RELATIVE_START]
        and body_opcodes == MULTI_PRED_BODY_OPCODE_SIGNATURES
    )


def _matches_side_effect_boundary_fixture(
    signature: dict[str, object] | None,
    *,
    block_count: int,
    maturity_name: str,
) -> bool:
    if signature is None:
        return False
    boundary = signature["boundary"]
    assert isinstance(boundary, dict)
    body_opcodes = signature["body_opcode_signatures_by_relative_start"]
    assert isinstance(body_opcodes, dict)
    call_targets = boundary["call_targets"]
    assert isinstance(call_targets, list)
    helper_ea = _required_name_ea(SIDE_EFFECT_HELPER_FUNCTION)
    return (
        maturity_name == EXPECTED_MATURITY
        and block_count == SIDE_EFFECT_EXPECTED_BLOCK_COUNT
        and boundary["type"] == "BLT_1WAY"
        and boundary["npred"] == 2
        and boundary["nsucc"] == 1
        and boundary["instruction_opcodes"]
        == SIDE_EFFECT_BOUNDARY_OPCODE_SIGNATURE
        and sorted(signature["boundary_pred_relative_start_eas"])
        == SIDE_EFFECT_BOUNDARY_INCOMING_RELATIVE_STARTS
        and signature["boundary_succ_relative_start_eas"]
        == [SIDE_EFFECT_BOUNDARY_SUCCESSOR_RELATIVE_START]
        and body_opcodes == SIDE_EFFECT_BODY_OPCODE_SIGNATURES
        and call_targets == [{
            "name": SIDE_EFFECT_HELPER_FUNCTION,
            "ea": helper_ea,
        }]
    )


def _matches_clean_fork_fixture(
    signature: dict[str, object] | None,
    *,
    block_count: int,
    maturity_name: str,
) -> bool:
    if signature is None:
        return False
    entry = signature["entry"]
    boundary = signature["boundary"]
    assert isinstance(entry, dict)
    assert isinstance(boundary, dict)
    body_opcodes = signature["body_opcode_signatures_by_relative_start"]
    assert isinstance(body_opcodes, dict)
    return (
        maturity_name == EXPECTED_MATURITY
        and block_count == CLEAN_FORK_EXPECTED_BLOCK_COUNT
        and entry["type"] == "BLT_2WAY"
        and entry["npred"] == 1
        and entry["nsucc"] == 2
        and entry["instruction_opcodes"] == CLEAN_FORK_ENTRY_OPCODE_SIGNATURE
        and signature["entry_succ_relative_start_eas"]
        == CLEAN_FORK_ENTRY_SUCCESSOR_RELATIVE_STARTS
        and signature["arm_paths_relative_start_eas"]
        == CLEAN_FORK_ARM_PATHS_RELATIVE_STARTS
        and boundary["type"] == "BLT_1WAY"
        and boundary["npred"] == 2
        and boundary["nsucc"] == 1
        and boundary["instruction_opcodes"] == CLEAN_FORK_JOIN_OPCODE_SIGNATURE
        and sorted(signature["boundary_pred_relative_start_eas"])
        == CLEAN_FORK_JOIN_INCOMING_RELATIVE_STARTS
        and signature["boundary_succ_relative_start_eas"]
        == [CLEAN_FORK_JOIN_SUCCESSOR_RELATIVE_START]
        and body_opcodes == CLEAN_FORK_BODY_OPCODE_SIGNATURES
    )


def _matches_conditional_shell_fixture(
    signature: dict[str, object] | None,
    *,
    block_count: int,
    maturity_name: str,
) -> bool:
    if signature is None:
        return False
    entry = signature["entry"]
    shell = signature["shell"]
    boundary = signature["boundary"]
    assert isinstance(entry, dict)
    assert isinstance(shell, dict)
    assert isinstance(boundary, dict)
    body_opcodes = signature["body_opcode_signatures_by_relative_start"]
    assert isinstance(body_opcodes, dict)
    return (
        maturity_name == EXPECTED_MATURITY
        and block_count == CONDITIONAL_SHELL_EXPECTED_BLOCK_COUNT
        and entry["type"] == "BLT_2WAY"
        and entry["npred"] == 1
        and entry["nsucc"] == 2
        and entry["instruction_opcodes"]
        == CONDITIONAL_SHELL_ENTRY_OPCODE_SIGNATURE
        and signature["entry_succ_relative_start_eas"]
        == CONDITIONAL_SHELL_ENTRY_SUCCESSOR_RELATIVE_STARTS
        and signature["entry_to_shell_paths_relative_start_eas"]
        == CONDITIONAL_SHELL_ENTRY_TO_SHELL_PATHS_RELATIVE_STARTS
        and shell["type"] == "BLT_2WAY"
        and shell["npred"] == 2
        and shell["nsucc"] == 2
        and shell["instruction_opcodes"] == CONDITIONAL_SHELL_OPCODE_SIGNATURE
        and sorted(signature["shell_pred_relative_start_eas"])
        == CONDITIONAL_SHELL_INCOMING_RELATIVE_STARTS
        and signature["shell_succ_relative_start_eas"]
        == CONDITIONAL_SHELL_SUCCESSOR_RELATIVE_STARTS
        and signature["shell_arm_paths_relative_start_eas"]
        == CONDITIONAL_SHELL_ARM_PATHS_RELATIVE_STARTS
        and boundary["type"] == "BLT_1WAY"
        and boundary["npred"] == 2
        and boundary["nsucc"] == 1
        and boundary["instruction_opcodes"]
        == CONDITIONAL_SHELL_BOUNDARY_OPCODE_SIGNATURE
        and sorted(signature["boundary_pred_relative_start_eas"])
        == CONDITIONAL_SHELL_BOUNDARY_INCOMING_RELATIVE_STARTS
        and signature["boundary_succ_relative_start_eas"]
        == [CONDITIONAL_SHELL_BOUNDARY_SUCCESSOR_RELATIVE_START]
        and body_opcodes == CONDITIONAL_SHELL_BODY_OPCODE_SIGNATURES
    )


def _matches_badwhile_direct_triangle_fixture(
    signature: dict[str, object] | None,
    *,
    block_count: int,
    maturity_name: str,
) -> bool:
    if signature is None:
        return False
    father = signature["father"]
    dispatcher = signature["dispatcher"]
    case_cond = signature["case_cond"]
    assert isinstance(father, dict)
    assert isinstance(dispatcher, dict)
    assert isinstance(case_cond, dict)
    return (
        maturity_name == EXPECTED_MATURITY
        and block_count == signature["block_count"]
        and father["type"] == "BLT_2WAY"
        and father["nsucc"] == 2
        and sorted(int(serial) for serial in father["succs"])
        == sorted([
            int(dispatcher["serial"]),
            int(case_cond["serial"]),
        ])
        and dispatcher["type"] == "BLT_2WAY"
        and dispatcher["nsucc"] == 2
        and int(case_cond["serial"]) in dispatcher["succs"]
        and case_cond["type"] == "BLT_2WAY"
        and case_cond["nsucc"] == 2
        and sorted(int(serial) for serial in case_cond["preds"])
        == sorted([
            int(father["serial"]),
            int(dispatcher["serial"]),
        ])
        and signature["father_to_case_intermediate_one_way_blocks"] == []
    )


def _matches_badwhile_trampoline_triangle_fixture(
    signature: dict[str, object] | None,
    *,
    block_count: int,
    maturity_name: str,
) -> bool:
    if signature is None:
        return False
    father = signature["father"]
    trampoline = signature["trampoline"]
    dispatcher = signature["dispatcher"]
    case_cond = signature["case_cond"]
    assert isinstance(father, dict)
    assert isinstance(trampoline, dict)
    assert isinstance(dispatcher, dict)
    assert isinstance(case_cond, dict)
    return (
        maturity_name == EXPECTED_MATURITY
        and block_count == signature["block_count"]
        and father["type"] == "BLT_2WAY"
        and father["nsucc"] == 2
        and sorted(int(serial) for serial in father["succs"])
        == sorted([
            int(trampoline["serial"]),
            int(dispatcher["serial"]),
        ])
        and trampoline["type"] == "BLT_1WAY"
        and trampoline["nsucc"] == 1
        and int(trampoline["succs"][0]) == int(case_cond["serial"])
        and signature["trampoline_is_minimal_goto_like"] is True
        and dispatcher["type"] == "BLT_2WAY"
        and dispatcher["nsucc"] == 2
        and int(case_cond["serial"]) in dispatcher["succs"]
        and case_cond["type"] == "BLT_2WAY"
        and case_cond["nsucc"] == 2
        and sorted(int(serial) for serial in case_cond["preds"])
        == sorted([
            int(trampoline["serial"]),
            int(dispatcher["serial"]),
        ])
        and signature["case_cond_has_father_direct_pred"] is False
    )


def _matches_badwhile_duplicate_group_triangle_fixture(
    signature: dict[str, object] | None,
    *,
    block_count: int,
    maturity_name: str,
) -> bool:
    if signature is None:
        return False
    pred_a = signature["pred_a"]
    pred_b = signature["pred_b"]
    shared = signature["shared"]
    dispatcher = signature["dispatcher"]
    case_cond = signature["case_cond"]
    assert isinstance(pred_a, dict)
    assert isinstance(pred_b, dict)
    assert isinstance(shared, dict)
    assert isinstance(dispatcher, dict)
    assert isinstance(case_cond, dict)
    pred_serials = [int(pred_a["serial"]), int(pred_b["serial"])]
    return (
        maturity_name == EXPECTED_MATURITY
        and block_count == signature["block_count"]
        and all(
            pred["type"] == "BLT_2WAY"
            and pred["nsucc"] == 2
            and sorted(int(serial) for serial in pred["succs"])
            == sorted([
                int(shared["serial"]),
                int(case_cond["serial"]),
            ])
            for pred in (pred_a, pred_b)
        )
        and shared["type"] == "BLT_1WAY"
        and shared["npred"] == 2
        and shared["nsucc"] == 1
        and sorted(int(serial) for serial in shared["preds"])
        == sorted(pred_serials)
        and int(shared["succs"][0]) == int(dispatcher["serial"])
        and dispatcher["type"] == "BLT_2WAY"
        and dispatcher["nsucc"] == 2
        and int(case_cond["serial"]) in dispatcher["succs"]
        and case_cond["type"] == "BLT_2WAY"
        and case_cond["nsucc"] == 2
        and sorted(int(serial) for serial in case_cond["preds"])
        == sorted(pred_serials + [int(dispatcher["serial"])])
    )


def _matches_badwhile_triangle_fixture(
    case_id: str,
    signature: dict[str, object] | None,
    *,
    block_count: int,
    maturity_name: str,
) -> bool:
    variant = BADWHILE_TRIANGLE_CASES[case_id]["variant"]
    if variant == "direct":
        return _matches_badwhile_direct_triangle_fixture(
            signature,
            block_count=block_count,
            maturity_name=maturity_name,
        )
    if variant == "trampoline":
        return _matches_badwhile_trampoline_triangle_fixture(
            signature,
            block_count=block_count,
            maturity_name=maturity_name,
        )
    if variant == "duplicate_group":
        return _matches_badwhile_duplicate_group_triangle_fixture(
            signature,
            block_count=block_count,
            maturity_name=maturity_name,
        )
    raise AssertionError(f"unknown bogus-loop triangle variant: {variant}")


def _case_expected(case_id: str) -> dict[str, object]:
    badwhile_case = BADWHILE_TRIANGLE_CASES.get(case_id)
    if badwhile_case is not None:
        expected = badwhile_case["expected"]
        assert isinstance(expected, dict)
        return expected

    terminal_tail_case = TERMINAL_TAIL_CASES.get(case_id)
    if terminal_tail_case is not None:
        expected = terminal_tail_case["expected"]
        assert isinstance(expected, dict)
        return expected

    if case_id == "single_pred_chain_merge":
        return {
            "accepted_maturity": EXPECTED_MATURITY,
            "block_count": f"== {EXPECTED_BLOCK_COUNT}",
            "chain_length": f"== {EXPECTED_CHAIN_LENGTH}",
            "body_relative_start_eas": EXPECTED_BODY_RELATIVE_STARTS,
            "body_opcode_signatures": EXPECTED_BODY_OPCODE_SIGNATURES,
            "body_opcode_names": [
                _opcode_names(opcodes)
                for opcodes in EXPECTED_BODY_OPCODE_SIGNATURES
            ],
            "edge_predicates": [
                f"BLT_1WAY chain length == {EXPECTED_CHAIN_LENGTH}",
                "each successor in the accepted chain has npred == 1",
                "each non-terminal chain block has nsucc == 1",
                "body block relative EA starts match the fixture label layout",
                "body opcode groups match the fixture operation sequence",
            ],
        }
    if case_id == "clean_conditional_fork":
        return {
            "accepted_maturity": EXPECTED_MATURITY,
            "block_count": f"== {CLEAN_FORK_EXPECTED_BLOCK_COUNT}",
            "entry_relative_start_ea": CLEAN_FORK_ENTRY_RELATIVE_START,
            "entry_opcode_signature": CLEAN_FORK_ENTRY_OPCODE_SIGNATURE,
            "entry_opcode_names": _opcode_names(
                CLEAN_FORK_ENTRY_OPCODE_SIGNATURE
            ),
            "entry_successor_relative_start_eas": (
                CLEAN_FORK_ENTRY_SUCCESSOR_RELATIVE_STARTS
            ),
            "arm_paths_relative_start_eas": (
                CLEAN_FORK_ARM_PATHS_RELATIVE_STARTS
            ),
            "join_relative_start_ea": CLEAN_FORK_JOIN_RELATIVE_START,
            "join_opcode_signature": CLEAN_FORK_JOIN_OPCODE_SIGNATURE,
            "join_opcode_names": _opcode_names(
                CLEAN_FORK_JOIN_OPCODE_SIGNATURE
            ),
            "join_incoming_relative_start_eas": (
                CLEAN_FORK_JOIN_INCOMING_RELATIVE_STARTS
            ),
            "join_successor_relative_start_ea": (
                CLEAN_FORK_JOIN_SUCCESSOR_RELATIVE_START
            ),
            "body_opcode_signatures_by_relative_start": (
                CLEAN_FORK_BODY_OPCODE_SIGNATURES
            ),
            "body_opcode_names_by_relative_start": {
                relative_start: _opcode_names(opcodes)
                for relative_start, opcodes
                in CLEAN_FORK_BODY_OPCODE_SIGNATURES.items()
            },
            "edge_predicates": [
                "entry block exists at fixture relative EA 0x0",
                "entry block has BLT_2WAY type with nsucc == 2",
                "entry successors are exactly relative EAs 0x1c and 0x1e",
                "entry arm paths are exactly 0x1c -> 0x58 -> 0x2e and 0x1e -> 0x44 -> 0x2e",
                "join block exists at fixture relative EA 0x2e",
                "join block has npred == 2 and nsucc == 1",
                "join predecessor relative EAs are exactly 0x44 and 0x58",
                "join successor relative EA is exactly 0x20",
                "body opcode groups match the fixture operation sequence",
            ],
        }
    if case_id == "conditional_shell_boundary":
        return {
            "accepted_maturity": EXPECTED_MATURITY,
            "block_count": f"== {CONDITIONAL_SHELL_EXPECTED_BLOCK_COUNT}",
            "entry_relative_start_ea": CONDITIONAL_SHELL_ENTRY_RELATIVE_START,
            "entry_opcode_signature": CONDITIONAL_SHELL_ENTRY_OPCODE_SIGNATURE,
            "entry_successor_relative_start_eas": (
                CONDITIONAL_SHELL_ENTRY_SUCCESSOR_RELATIVE_STARTS
            ),
            "entry_to_shell_paths_relative_start_eas": (
                CONDITIONAL_SHELL_ENTRY_TO_SHELL_PATHS_RELATIVE_STARTS
            ),
            "shell_relative_start_ea": CONDITIONAL_SHELL_RELATIVE_START,
            "shell_opcode_signature": CONDITIONAL_SHELL_OPCODE_SIGNATURE,
            "shell_incoming_relative_start_eas": (
                CONDITIONAL_SHELL_INCOMING_RELATIVE_STARTS
            ),
            "shell_successor_relative_start_eas": (
                CONDITIONAL_SHELL_SUCCESSOR_RELATIVE_STARTS
            ),
            "shell_arm_paths_relative_start_eas": (
                CONDITIONAL_SHELL_ARM_PATHS_RELATIVE_STARTS
            ),
            "boundary_relative_start_ea": (
                CONDITIONAL_SHELL_BOUNDARY_RELATIVE_START
            ),
            "boundary_opcode_signature": (
                CONDITIONAL_SHELL_BOUNDARY_OPCODE_SIGNATURE
            ),
            "boundary_incoming_relative_start_eas": (
                CONDITIONAL_SHELL_BOUNDARY_INCOMING_RELATIVE_STARTS
            ),
            "boundary_successor_relative_start_ea": (
                CONDITIONAL_SHELL_BOUNDARY_SUCCESSOR_RELATIVE_START
            ),
            "body_opcode_signatures_by_relative_start": (
                CONDITIONAL_SHELL_BODY_OPCODE_SIGNATURES
            ),
            "body_opcode_names_by_relative_start": {
                relative_start: _opcode_names(opcodes)
                for relative_start, opcodes
                in CONDITIONAL_SHELL_BODY_OPCODE_SIGNATURES.items()
            },
            "edge_predicates": [
                "entry block exists at fixture relative EA 0x0",
                "entry block has BLT_2WAY type with nsucc == 2",
                "entry-to-shell paths are exactly 0x1b -> 0x76 and 0x1d -> 0x62 -> 0x76",
                "shell block exists at fixture relative EA 0x76",
                "shell block has npred == 2 and nsucc == 2",
                "shell arm paths are exactly 0x84 -> 0x57 -> 0x41 and 0x86 -> 0x41",
                "boundary block exists at fixture relative EA 0x41",
                "boundary block has npred == 2 and nsucc == 1",
                "body opcode groups match the fixture operation sequence",
            ],
        }
    if case_id == "multi_pred_boundary_barrier":
        return {
            "accepted_maturity": EXPECTED_MATURITY,
            "block_count": f"== {MULTI_PRED_EXPECTED_BLOCK_COUNT}",
            "boundary_relative_start_ea": MULTI_PRED_BOUNDARY_RELATIVE_START,
            "boundary_opcode_signature": MULTI_PRED_BOUNDARY_OPCODE_SIGNATURE,
            "boundary_opcode_names": _opcode_names(
                MULTI_PRED_BOUNDARY_OPCODE_SIGNATURE
            ),
            "boundary_incoming_relative_start_eas": (
                MULTI_PRED_BOUNDARY_INCOMING_RELATIVE_STARTS
            ),
            "boundary_successor_relative_start_ea": (
                MULTI_PRED_BOUNDARY_SUCCESSOR_RELATIVE_START
            ),
            "body_opcode_signatures_by_relative_start": (
                MULTI_PRED_BODY_OPCODE_SIGNATURES
            ),
            "body_opcode_names_by_relative_start": {
                relative_start: _opcode_names(opcodes)
                for relative_start, opcodes
                in MULTI_PRED_BODY_OPCODE_SIGNATURES.items()
            },
            "edge_predicates": [
                "boundary block exists at fixture relative EA 0x55",
                "boundary block has npred == 2 and nsucc == 1",
                "boundary predecessor relative EAs are exactly 0x1b and 0x41",
                "boundary successor relative EA is exactly 0x2d",
                "body opcode groups match the fixture operation sequence",
            ],
        }
    if case_id == "side_effect_boundary_anchor":
        return {
            "accepted_maturity": EXPECTED_MATURITY,
            "block_count": f"== {SIDE_EFFECT_EXPECTED_BLOCK_COUNT}",
            "boundary_relative_start_ea": SIDE_EFFECT_BOUNDARY_RELATIVE_START,
            "boundary_opcode_signature": SIDE_EFFECT_BOUNDARY_OPCODE_SIGNATURE,
            "boundary_opcode_names": _opcode_names(
                SIDE_EFFECT_BOUNDARY_OPCODE_SIGNATURE
            ),
            "boundary_incoming_relative_start_eas": (
                SIDE_EFFECT_BOUNDARY_INCOMING_RELATIVE_STARTS
            ),
            "boundary_successor_relative_start_ea": (
                SIDE_EFFECT_BOUNDARY_SUCCESSOR_RELATIVE_START
            ),
            "boundary_call_target_name": SIDE_EFFECT_HELPER_FUNCTION,
            "boundary_call_target_ea": _required_name_ea(
                SIDE_EFFECT_HELPER_FUNCTION
            ),
            "body_opcode_signatures_by_relative_start": (
                SIDE_EFFECT_BODY_OPCODE_SIGNATURES
            ),
            "body_opcode_names_by_relative_start": {
                relative_start: _opcode_names(opcodes)
                for relative_start, opcodes
                in SIDE_EFFECT_BODY_OPCODE_SIGNATURES.items()
            },
            "edge_predicates": [
                "boundary block exists at fixture relative EA 0x64",
                "boundary block has npred == 2 and nsucc == 1",
                "boundary predecessor relative EAs are exactly 0x1f and 0x4d",
                "boundary successor relative EA is exactly 0x81",
                (
                    "boundary body calls hexrays_lab_boundary_anchor_helper "
                    "as the noinline volatile anchor"
                ),
                "body opcode groups match the fixture operation sequence",
            ],
        }
    raise AssertionError(f"unknown lab case: {case_id}")


def _case_match(
    case_id: str,
    ida_hexrays,
    mba,
    *,
    func_ea: int,
    maturity_name: str,
) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    blocks = [
        _block_record(ida_hexrays, mba.get_mblock(index))
        for index in range(mba.qty)
        if mba.get_mblock(index) is not None
    ]
    if case_id == "single_pred_chain_merge":
        candidate_chains = [
            _chain_signature(ida_hexrays, mba, chain, func_ea=func_ea)
            for chain in _find_single_pred_chains(ida_hexrays, mba)
        ]
        for signature in candidate_chains:
            if _matches_single_pred_chain_fixture(
                signature,
                block_count=int(mba.qty),
                maturity_name=maturity_name,
            ):
                return signature, candidate_chains
        return None, candidate_chains

    if case_id == "multi_pred_boundary_barrier":
        signature = _multi_pred_boundary_signature(blocks, func_ea=func_ea)
        candidates = [signature] if signature is not None else []
        if _matches_multi_pred_boundary_fixture(
            signature,
            block_count=int(mba.qty),
            maturity_name=maturity_name,
        ):
            return signature, candidates
        return None, candidates

    if case_id == "side_effect_boundary_anchor":
        signature = _side_effect_boundary_signature(blocks, func_ea=func_ea)
        candidates = [signature] if signature is not None else []
        if _matches_side_effect_boundary_fixture(
            signature,
            block_count=int(mba.qty),
            maturity_name=maturity_name,
        ):
            return signature, candidates
        return None, candidates

    if case_id == "clean_conditional_fork":
        signature = _clean_fork_signature(blocks, func_ea=func_ea)
        candidates = [signature] if signature is not None else []
        if _matches_clean_fork_fixture(
            signature,
            block_count=int(mba.qty),
            maturity_name=maturity_name,
        ):
            return signature, candidates
        return None, candidates

    if case_id == "conditional_shell_boundary":
        signature = _conditional_shell_signature(blocks, func_ea=func_ea)
        candidates = [signature] if signature is not None else []
        if _matches_conditional_shell_fixture(
            signature,
            block_count=int(mba.qty),
            maturity_name=maturity_name,
        ):
            return signature, candidates
        return None, candidates

    if case_id in BADWHILE_TRIANGLE_CASES:
        signature = _badwhile_triangle_signature(
            case_id,
            blocks,
            func_ea=func_ea,
        )
        candidates = [signature] if signature is not None else []
        if _matches_badwhile_triangle_fixture(
            case_id,
            signature,
            block_count=int(mba.qty),
            maturity_name=maturity_name,
        ):
            return signature, candidates
        return None, candidates

    if case_id == "terminal_tail_ref_cascade":
        signature = _terminal_tail_ref_cascade_signature(
            blocks,
            func_ea=func_ea,
        )
        candidates = [signature] if signature is not None else []
        if _matches_terminal_tail_ref_cascade_fixture(
            signature,
            block_count=int(mba.qty),
            maturity_name=maturity_name,
        ):
            return signature, candidates
        return None, candidates

    if case_id == "terminal_tail_shared_convergence":
        signature = _terminal_tail_shared_convergence_signature(
            blocks,
            func_ea=func_ea,
        )
        candidates = [signature] if signature is not None else []
        if _matches_terminal_tail_shared_convergence_fixture(
            signature,
            block_count=int(mba.qty),
            maturity_name=maturity_name,
        ):
            return signature, candidates
        return None, candidates

    if case_id == "terminal_tail_split_guard":
        signature = _terminal_tail_split_guard_signature(
            blocks,
            func_ea=func_ea,
        )
        candidates = [signature] if signature is not None else []
        if _matches_terminal_tail_split_guard_fixture(
            signature,
            block_count=int(mba.qty),
            maturity_name=maturity_name,
        ):
            return signature, candidates
        return None, candidates

    if case_id == "terminal_tail_unique_continuation":
        signature = _terminal_tail_unique_continuation_signature(
            blocks,
            func_ea=func_ea,
        )
        candidates = [signature] if signature is not None else []
        if _matches_terminal_tail_unique_continuation_fixture(
            signature,
            block_count=int(mba.qty),
            maturity_name=maturity_name,
        ):
            return signature, candidates
        return None, candidates

    if case_id in TERMINAL_TAIL_CASES:
        signature = _terminal_tail_candidate_signature(blocks, func_ea=func_ea)
        return None, [signature]

    raise AssertionError(f"unknown lab case: {case_id}")


def _maturity_results(
    case_id: str,
    func_ea: int,
) -> tuple[list[dict[str, object]], dict[str, object] | None]:
    import ida_hexrays

    maturities = [
        ("MMAT_GENERATED", ida_hexrays.MMAT_GENERATED),
        ("MMAT_PREOPTIMIZED", ida_hexrays.MMAT_PREOPTIMIZED),
        ("MMAT_LOCOPT", ida_hexrays.MMAT_LOCOPT),
    ]
    results = []
    passed = None
    for maturity_name, maturity in maturities:
        mba = gen_microcode_at_maturity(func_ea, maturity)
        if mba is None:
            result = {
                "maturity": maturity_name,
                "maturity_id": int(maturity),
                "status": "microcode_generation_failed",
            }
            results.append(result)
            continue

        matching_signature, candidates = _case_match(
            case_id,
            ida_hexrays,
            mba,
            func_ea=func_ea,
            maturity_name=maturity_name,
        )
        blocks = [
            _block_record(ida_hexrays, mba.get_mblock(index))
            for index in range(mba.qty)
            if mba.get_mblock(index) is not None
        ]
        result = {
            "maturity": maturity_name,
            "maturity_id": int(maturity),
            "status": "passed" if matching_signature is not None else "failed",
            "block_count": int(mba.qty),
            "matching_signature": matching_signature,
            "matching_chain": (
                matching_signature
                if case_id == "single_pred_chain_merge"
                else None
            ),
            "matching_chain_length": (
                matching_signature["chain_length"]
                if (
                    case_id == "single_pred_chain_merge"
                    and matching_signature is not None
                )
                else 0
            ),
            "candidate_count": len(candidates),
            "candidates": candidates,
            "blocks": blocks,
        }
        results.append(result)
        if passed is None and matching_signature is not None:
            passed = result
    return results, passed


def _write_artifact(path: Path, artifact: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n")


class TestHexraysStructuringLabCfgValidation:
    binary_name = os.environ.get("D810_TEST_BINARY", "libobfuscated.dll")

    def test_single_pred_chain_merge_compiled_cfg(
        self,
        request,
        ida_database,
        configure_hexrays,
        setup_libobfuscated_funcs,
    ) -> None:
        import idaapi

        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")

        case_id = request.config.getoption("--hexrays-lab-case") or DEFAULT_CASE_ID
        if case_id not in CASE_DEFAULTS:
            raise AssertionError(f"unknown lab case: {case_id}")
        case_defaults = CASE_DEFAULTS[case_id]
        function = (
            request.config.getoption("--hexrays-lab-function")
            or str(case_defaults["function"])
        )
        output_json = (
            request.config.getoption("--hexrays-lab-output-json")
            or str(case_defaults["output_json"])
        )
        artifact_path = Path(output_json)
        binary_path = Path(ida_database.get("binary_path", ""))
        compiler_flags = ["-O0"]
        expected = _case_expected(case_id)

        func_ea = get_func_ea(function)
        artifact: dict[str, object] = {
            "case_id": case_id,
            "function": function,
            "status": "failed",
            "compiler_flags": compiler_flags,
            "binary": self.binary_name,
            "binary_hash": _sha256(binary_path),
            "artifact_path": str(artifact_path),
            "expected": expected,
            "observed": {
                "function_ea": None,
                "maturities": [],
            },
        }

        if func_ea == idaapi.BADADDR:
            artifact["observed"] = {
                "function_ea": None,
                "error": f"function not found: {function}",
            }
            _write_artifact(artifact_path, artifact)
            raise AssertionError(f"function not found: {function}")

        maturity_results, passed = _maturity_results(case_id, func_ea)
        accepted_signature = (
            passed["matching_signature"] if passed is not None else None
        )
        accepted_chain = (
            passed["matching_chain"]["serials"]
            if (
                passed is not None
                and passed["matching_chain"] is not None
            )
            else None
        )
        artifact["observed"] = {
            "function_ea": f"0x{func_ea:x}",
            "maturities": maturity_results,
            "accepted_maturity": passed["maturity"] if passed else None,
            "accepted_chain": accepted_chain,
            "accepted_chain_length": (
                passed["matching_chain_length"] if passed else 0
            ),
            "accepted_signature": accepted_signature,
        }
        artifact["status"] = "passed" if passed is not None else "failed"
        _write_artifact(artifact_path, artifact)

        assert passed is not None, (
            "compiled CFG does not contain the exact expected "
            f"{case_id} fixture shape for {function}; "
            f"validation artifact: {artifact_path}"
        )

        observed = dict(artifact["observed"])
        if case_id == "single_pred_chain_merge":
            accepted = observed["accepted_chain"]
            assert isinstance(accepted, list)
            assert len(accepted) == EXPECTED_CHAIN_LENGTH
        elif case_id in {
            "multi_pred_boundary_barrier",
            "side_effect_boundary_anchor",
            "clean_conditional_fork",
            "conditional_shell_boundary",
        }:
            signature = observed["accepted_signature"]
            assert isinstance(signature, dict)
            boundary = signature["boundary"]
            assert isinstance(boundary, dict)
            assert boundary["npred"] == 2
            expected_opcodes = {
                "multi_pred_boundary_barrier": (
                    MULTI_PRED_BOUNDARY_OPCODE_SIGNATURE
                ),
                "side_effect_boundary_anchor": (
                    SIDE_EFFECT_BOUNDARY_OPCODE_SIGNATURE
                ),
                "clean_conditional_fork": CLEAN_FORK_JOIN_OPCODE_SIGNATURE,
                "conditional_shell_boundary": (
                    CONDITIONAL_SHELL_BOUNDARY_OPCODE_SIGNATURE
                ),
            }[case_id]
            assert boundary["instruction_opcodes"] == expected_opcodes
            if case_id == "side_effect_boundary_anchor":
                helper_ea = _required_name_ea(SIDE_EFFECT_HELPER_FUNCTION)
                assert boundary["call_targets"] == [{
                    "name": SIDE_EFFECT_HELPER_FUNCTION,
                    "ea": helper_ea,
                }]
            if case_id == "clean_conditional_fork":
                entry = signature["entry"]
                assert isinstance(entry, dict)
                assert entry["type"] == "BLT_2WAY"
                assert entry["instruction_opcodes"] == (
                    CLEAN_FORK_ENTRY_OPCODE_SIGNATURE
                )
                assert signature["arm_paths_relative_start_eas"] == (
                    CLEAN_FORK_ARM_PATHS_RELATIVE_STARTS
                )
            if case_id == "conditional_shell_boundary":
                shell = signature["shell"]
                assert isinstance(shell, dict)
                assert shell["type"] == "BLT_2WAY"
                assert shell["instruction_opcodes"] == (
                    CONDITIONAL_SHELL_OPCODE_SIGNATURE
                )
                assert signature["entry_to_shell_paths_relative_start_eas"] == (
                    CONDITIONAL_SHELL_ENTRY_TO_SHELL_PATHS_RELATIVE_STARTS
                )
                assert signature["shell_arm_paths_relative_start_eas"] == (
                    CONDITIONAL_SHELL_ARM_PATHS_RELATIVE_STARTS
                )
            if case_id == "terminal_tail_ref_cascade":
                guards = signature["guards"]
                return_epilogue = signature["return_epilogue"]
                assert isinstance(guards, list)
                assert isinstance(return_epilogue, dict)
                assert len(guards) == 6
                assert [guard["type"] for guard in guards] == ["BLT_2WAY"] * 6
                assert return_epilogue["npred"] == 7
            if case_id == "terminal_tail_shared_convergence":
                shared_guard = signature["shared_guard"]
                byte_emits = signature["byte_emits"]
                assert isinstance(shared_guard, dict)
                assert isinstance(byte_emits, list)
                assert shared_guard["npred"] == 7
                assert len(byte_emits) == 7
                assert [
                    block["succs"][0]
                    for block in byte_emits
                ] == [shared_guard["serial"]] * 7
            if case_id == "terminal_tail_unique_continuation":
                shared_guard = signature["shared_guard"]
                byte_emits = signature["byte_emits"]
                assert isinstance(shared_guard, dict)
                assert isinstance(byte_emits, list)
                assert shared_guard["npred"] == 7
                assert len(byte_emits) == 7
                assert [
                    block["succs"][0]
                    for block in byte_emits
                ] == [shared_guard["serial"]] * 7
            if case_id == "terminal_tail_split_guard":
                guards = signature["guards"]
                return_epilogue = signature["return_epilogue"]
                assert isinstance(guards, list)
                assert isinstance(return_epilogue, dict)
                assert len(guards) == 6
                assert [guard["type"] for guard in guards] == ["BLT_2WAY"] * 6
                assert return_epilogue["npred"] == 7
        elif case_id in BADWHILE_TRIANGLE_CASES:
            signature = observed["accepted_signature"]
            assert isinstance(signature, dict)
            case_cond = signature["case_cond"]
            dispatcher = signature["dispatcher"]
            assert isinstance(case_cond, dict)
            assert isinstance(dispatcher, dict)
            assert case_cond["type"] == "BLT_2WAY"
            assert case_cond["nsucc"] == 2
            assert int(case_cond["serial"]) in dispatcher["succs"]
            variant = BADWHILE_TRIANGLE_CASES[case_id]["variant"]
            if variant == "direct":
                father = signature["father"]
                assert isinstance(father, dict)
                assert int(case_cond["serial"]) in father["succs"]
                assert signature[
                    "father_to_case_intermediate_one_way_blocks"
                ] == []
            if variant == "trampoline":
                father = signature["father"]
                trampoline = signature["trampoline"]
                assert isinstance(father, dict)
                assert isinstance(trampoline, dict)
                assert int(case_cond["serial"]) not in father["succs"]
                assert int(trampoline["serial"]) in father["succs"]
                assert trampoline["nsucc"] == 1
                assert int(trampoline["succs"][0]) == int(case_cond["serial"])
                assert signature["case_cond_has_father_direct_pred"] is False
                assert signature["trampoline_is_minimal_goto_like"] is True
            if variant == "duplicate_group":
                pred_a = signature["pred_a"]
                pred_b = signature["pred_b"]
                shared = signature["shared"]
                assert isinstance(pred_a, dict)
                assert isinstance(pred_b, dict)
                assert isinstance(shared, dict)
                assert shared["npred"] == 2
                for pred in (pred_a, pred_b):
                    assert int(shared["serial"]) in pred["succs"]
                    assert int(case_cond["serial"]) in pred["succs"]
