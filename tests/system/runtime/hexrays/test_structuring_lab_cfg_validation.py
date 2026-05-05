"""Compiled-CFG validation for Hex-Rays structuring lab fixtures."""
from __future__ import annotations

import hashlib
import json
import os
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


def _block_record(ida_hexrays, blk) -> dict[str, object]:
    instruction_opcodes = _instruction_opcodes(blk)
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
        "instruction_count": len(instruction_opcodes),
        "instruction_opcodes": instruction_opcodes,
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


def _maturity_results(
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

        candidate_chains = [
            _chain_signature(ida_hexrays, mba, chain, func_ea=func_ea)
            for chain in _find_single_pred_chains(ida_hexrays, mba)
        ]
        matching_chain = None
        for signature in candidate_chains:
            if _matches_single_pred_chain_fixture(
                signature,
                block_count=int(mba.qty),
                maturity_name=maturity_name,
            ):
                matching_chain = signature
                break
        blocks = [
            _block_record(ida_hexrays, mba.get_mblock(index))
            for index in range(mba.qty)
            if mba.get_mblock(index) is not None
        ]
        result = {
            "maturity": maturity_name,
            "maturity_id": int(maturity),
            "status": "passed" if matching_chain is not None else "failed",
            "block_count": int(mba.qty),
            "matching_chain": matching_chain,
            "matching_chain_length": (
                matching_chain["chain_length"] if matching_chain is not None else 0
            ),
            "candidate_chain_count": len(candidate_chains),
            "candidate_chains": candidate_chains,
            "blocks": blocks,
        }
        results.append(result)
        if passed is None and matching_chain is not None:
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
        function = (
            request.config.getoption("--hexrays-lab-function")
            or DEFAULT_FUNCTION
        )
        output_json = (
            request.config.getoption("--hexrays-lab-output-json")
            or DEFAULT_OUTPUT_JSON
        )
        artifact_path = Path(output_json)
        binary_path = Path(ida_database.get("binary_path", ""))
        compiler_flags = ["-O0"]
        expected = {
            "accepted_maturity": EXPECTED_MATURITY,
            "block_count": f"== {EXPECTED_BLOCK_COUNT}",
            "chain_length": f"== {EXPECTED_CHAIN_LENGTH}",
            "body_relative_start_eas": EXPECTED_BODY_RELATIVE_STARTS,
            "body_opcode_signatures": EXPECTED_BODY_OPCODE_SIGNATURES,
            "edge_predicates": [
                f"BLT_1WAY chain length == {EXPECTED_CHAIN_LENGTH}",
                "each successor in the accepted chain has npred == 1",
                "each non-terminal chain block has nsucc == 1",
                "body block relative EA starts match the fixture label layout",
                "body opcode groups match the fixture operation sequence",
            ],
        }

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

        maturity_results, passed = _maturity_results(func_ea)
        artifact["observed"] = {
            "function_ea": f"0x{func_ea:x}",
            "maturities": maturity_results,
            "accepted_maturity": passed["maturity"] if passed else None,
            "accepted_chain": (
                passed["matching_chain"]["serials"] if passed else None
            ),
            "accepted_chain_length": (
                passed["matching_chain_length"] if passed else 0
            ),
            "accepted_signature": passed["matching_chain"] if passed else None,
        }
        artifact["status"] = "passed" if passed is not None else "failed"
        _write_artifact(artifact_path, artifact)

        assert passed is not None, (
            "compiled CFG does not contain the exact expected "
            "single_pred_chain_merge fixture chain for "
            f"{function}; validation artifact: {artifact_path}"
        )

        accepted = dict(artifact["observed"])["accepted_chain"]
        assert isinstance(accepted, list)
        assert len(accepted) == EXPECTED_CHAIN_LENGTH
