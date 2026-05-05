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
}


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
    return _hex_ea(int(ea))


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
            "ea": _name_ea(SIDE_EFFECT_HELPER_FUNCTION),
        }]
    )


def _case_expected(case_id: str) -> dict[str, object]:
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
            "boundary_call_target_ea": _name_ea(SIDE_EFFECT_HELPER_FUNCTION),
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
        }:
            signature = observed["accepted_signature"]
            assert isinstance(signature, dict)
            boundary = signature["boundary"]
            assert isinstance(boundary, dict)
            assert boundary["npred"] == 2
            expected_opcodes = (
                MULTI_PRED_BOUNDARY_OPCODE_SIGNATURE
                if case_id == "multi_pred_boundary_barrier"
                else SIDE_EFFECT_BOUNDARY_OPCODE_SIGNATURE
            )
            assert boundary["instruction_opcodes"] == expected_opcodes
            if case_id == "side_effect_boundary_anchor":
                assert boundary["call_targets"] == [{
                    "name": SIDE_EFFECT_HELPER_FUNCTION,
                    "ea": _name_ea(SIDE_EFFECT_HELPER_FUNCTION),
                }]
