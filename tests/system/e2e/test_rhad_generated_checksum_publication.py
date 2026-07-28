"""Exact A560 GENERATED checksum canary through ctree generation."""

from __future__ import annotations

import hashlib
import faulthandler
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import sys

import pytest


idapro = pytest.importorskip("idapro")

_REPO = pathlib.Path(__file__).resolve().parents[3]
_BINARY = _REPO / "samples" / "bins" / "rhad_loader_unpacked.bin"
_FUNCTION_EA = 0x40A560
_EXPECTED_SHA256 = "2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c"
_SIDECARS = (".id0", ".id1", ".id2", ".nam", ".til", ".i64")
_FAILURE_OUTPUT_LIMIT = 12_000
_REFERENCE_OPERATION_IDS = (
    "rhad:route@0x40A605",
    "route:rhad-direct@0x40A619",
    "route:rhad-direct@0x40A631",
    "route:rhad-direct@0x40A649",
    "route:rhad-direct@0x40A661",
    "route:rhad-direct@0x40A679",
    "route:rhad-direct@0x40A68A",
    "rhad:route@0x40A6A4",
    "rhad:route@0x40A6BE",
    "rhad:route@0x40A6D8",
    "rhad:route@0x40A6F2",
    "rhad:route@0x40A70C",
    "route:rhad-direct@0x40A74A",
    "rhad:route@0x40A764",
    "rhad:route@0x40A77C",
    "rhad:route@0x40A792",
    "rhad:route@0x40A7AC",
    "route:rhad-direct@0x40A7EF",
    "rhad:route@0x40A818",
    "rhad:route@0x40A832",
    "rhad:route@0x40A84C",
    "rhad:route@0x40A866",
    "route:rhad-direct@0x40A8B3",
    "rhad:route@0x40A8CD",
    "rhad:route@0x40A8E7",
    "rhad:route@0x40A901",
    "route:rhad-direct@0x40A95E",
    "rhad:route@0x40A978",
    "rhad:route@0x40A992",
    "rhad:route@0x40A9AC",
    "rhad:route@0x40A9DC",
    "rhad:route@0x40A9F6",
    "rhad:route@0x40AA10",
    "rhad:route@0x40AA2A",
    "rhad:route@0x40AA5E",
    "rhad:route@0x40AA78",
    "rhad:route@0x40AA92",
    "rhad:route@0x40AAAC",
    "route:rhad-direct@0x40AAFB",
    "rhad:route@0x40AB15",
    "rhad:route@0x40AB2F",
    "route:rhad-direct@0x40AB74",
    "rhad:route@0x40AB8E",
    "rhad:route@0x40ABA8",
    "rhad:route@0x40ABDE",
    "rhad:route@0x40ABF8",
    "route:rhad-direct@0x40AC3B",
    "rhad:route@0x40AC54",
    "rhad:route@0x40AC6E",
    "route:rhad-direct@0x40ACBD",
    "rhad:route@0x40ACD7",
    "rhad:route@0x40ACF1",
    "route:rhad-direct@0x40AD1C",
    "rhad:route@0x40AD36",
    "rhad:route@0x40AD50",
    "rhad:route@0x40AD6C",
    "rhad:route@0x40AD86",
    "rhad:route@0x40ADA0",
    "rhad:route@0x40ADBC",
    "rhad:route@0x40ADD6",
    "rhad:route@0x40ADF0",
    "rhad:route@0x40AE18",
    "route:rhad-direct@0x40AE24",
    "rhad:route@0x40AE3C",
    "rhad:route@0x40AE89",
    "rhad:route@0x40AEA3",
    "route:rhad-direct@0x40AEE4",
    "rhad:route@0x40AEFE",
    "route:rhad-direct@0x40AFDD",
    "rhad:route@0x40AFF7",
    "route:rhad-direct@0x40B022",
    "rhad:route@0x40B03C",
    "route:rhad-direct@0x40B06F",
    "rhad:route@0x40B089",
    "rhad:route@0x40B0BA",
)
_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
    "native@0x40B6C0",
    "native@0x40B6CA",
    "native@0x40B6D0",
    "native@0x40B6D4",
    "native@0x40A61B",
    "native@0x40A62D",
    "native@0x40A631",
    "native@0x40A740",
    "native@0x40A74A",
    "native@0x40A68C",
    "native@0x40A69A",
    "native@0x40A6A0",
    "native@0x40A6A4",
    "native@0x40A6A6",
    "native@0x40A6B4",
    "native@0x40A6BA",
    "native@0x40A800",
    "native@0x40A80E",
    "native@0x40A814",
    "native@0x40A818",
    "native@0x40A6C0",
    "native@0x40A6CE",
    "native@0x40A6D4",
    "native@0x40A6D8",
    "native@0x40A960",
    "native@0x40A96E",
    "native@0x40A974",
    "native@0x40A978",
    "native@0x40A6DA",
    "native@0x40A6E8",
    "native@0x40A6EE",
    "native@0x40A6F2",
    "native@0x40AB76",
    "native@0x40AB84",
    "native@0x40AB8A",
    "native@0x40AB8E",
    "native@0x40A6F4",
    "native@0x40A702",
    "native@0x40A708",
    "native@0x40A70C",
    "native@0x40AE8B",
    "native@0x40AE99",
    "native@0x40AE9F",
    "native@0x40AEA3",
    "native@0x40A70E",
    "native@0x40A736",
    "native@0x40A739",
    "native@0x40A73D",
    "native@0x40A74C",
    "native@0x40A75A",
    "native@0x40A760",
    "native@0x40A764",
    "native@0x40A766",
    "native@0x40ABC6",
    "native@0x40ABD4",
    "native@0x40ABDA",
    "native@0x40ABDE",
    "native@0x40A77C",
    "native@0x40A9DE",
    "native@0x40A9EC",
    "native@0x40A9F2",
    "native@0x40A9F6",
    "native@0x40A77E",
    "native@0x40A794",
    "native@0x40A7A2",
    "native@0x40A7A8",
    "native@0x40A7AC",
    "native@0x40AEE6",
    "native@0x40AEF4",
    "native@0x40AEFA",
    "native@0x40AEFE",
    "native@0x40A7AE",
    "native@0x40A7BA",
    "native@0x40A7CD",
    "native@0x40A7E5",
    "native@0x40A7EF",
    "native@0x40B4C5",
    "native@0x40B4E2",
    "native@0x40B4EE",
    "native@0x40A81A",
    "native@0x40A828",
    "native@0x40A82E",
    "native@0x40A832",
    "native@0x40AA60",
    "native@0x40AA6E",
    "native@0x40AA74",
    "native@0x40AA78",
    "native@0x40A834",
    "native@0x40A842",
    "native@0x40A848",
    "native@0x40A84C",
    "native@0x40AC3D",
    "native@0x40AC4A",
    "native@0x40AC50",
    "native@0x40AC54",
    "native@0x40A84E",
    "native@0x40A85C",
    "native@0x40A862",
    "native@0x40A866",
    "native@0x40AFDF",
    "native@0x40AFED",
    "native@0x40AFF3",
    "native@0x40AFF7",
    "native@0x40A868",
    "native@0x40A8A0",
    "native@0x40A8A3",
    "native@0x40A8A7",
    "native@0x40A633",
    "native@0x40A645",
    "native@0x40A649",
    "native@0x40A8A9",
    "native@0x40A8B3",
    "native@0x40A64B",
    "native@0x40A65D",
    "native@0x40A661",
    "native@0x40AAF1",
    "native@0x40AAFB",
    "native@0x40A663",
    "native@0x40A675",
    "native@0x40A679",
    "native@0x40AE1A",
    "native@0x40AE24",
    "native@0x40AE26",
    "native@0x40AE3C",
    "native@0x40A8B5",
    "native@0x40A8C3",
    "native@0x40A8C9",
    "native@0x40A8CD",
    "native@0x40A8CF",
    "native@0x40A8DD",
    "native@0x40A8E3",
    "native@0x40A8E7",
    "native@0x40ACBF",
    "native@0x40ACCD",
    "native@0x40ACD3",
    "native@0x40ACD7",
    "native@0x40A8E9",
    "native@0x40A8F7",
    "native@0x40A8FD",
    "native@0x40A901",
    "native@0x40B024",
    "native@0x40B032",
    "native@0x40B038",
    "native@0x40B03C",
    "native@0x40A903",
    "native@0x40A922",
    "native@0x40A93C",
    "native@0x40A954",
    "native@0x40A95E",
    "native@0x40B4F0",
    "native@0x40B50D",
    "native@0x40B519",
    "native@0x40A97A",
    "native@0x40A988",
    "native@0x40A98E",
    "native@0x40A992",
    "native@0x40AD1E",
    "native@0x40AD2C",
    "native@0x40AD32",
    "native@0x40AD36",
    "native@0x40A994",
    "native@0x40A9A2",
    "native@0x40A9A8",
    "native@0x40A9AC",
    "native@0x40B071",
    "native@0x40B07F",
    "native@0x40B085",
    "native@0x40B089",
    "native@0x40A9AE",
    "native@0x40A9D5",
    "native@0x40A9D8",
    "native@0x40A9DC",
    "native@0x40A9F8",
    "native@0x40AA06",
    "native@0x40AA0C",
    "native@0x40AA10",
    "native@0x40AD6E",
    "native@0x40AD7C",
    "native@0x40AD82",
    "native@0x40AD86",
    "native@0x40AA12",
    "native@0x40AA20",
    "native@0x40AA26",
    "native@0x40AA2A",
    "native@0x40B0BC",
    "native@0x40B0CA",
    "native@0x40B0D0",
    "native@0x40B0D4",
    "native@0x40AA2C",
    "native@0x40AA35",
    "native@0x40AA57",
    "native@0x40AA5A",
    "native@0x40AA5E",
    "native@0x40AA7A",
    "native@0x40AA88",
    "native@0x40AA8E",
    "native@0x40AA92",
    "native@0x40ADBE",
    "native@0x40ADCC",
    "native@0x40ADD2",
    "native@0x40ADD6",
    "native@0x40AA94",
    "native@0x40AAA2",
    "native@0x40AAA8",
    "native@0x40AAAC",
    "native@0x40B0F2",
    "native@0x40B100",
    "native@0x40B106",
    "native@0x40B10A",
    "native@0x40AAAE",
    "native@0x40AAE8",
    "native@0x40AAEB",
    "native@0x40AAEF",
    "native@0x40AAFD",
    "native@0x40AB0B",
    "native@0x40AB11",
    "native@0x40AB15",
    "native@0x40AB17",
    "native@0x40AB25",
    "native@0x40AB2B",
    "native@0x40AB2F",
    "native@0x40B149",
    "native@0x40B157",
    "native@0x40B15D",
    "native@0x40B161",
    "native@0x40AB31",
    "native@0x40AB56",
    "native@0x40AB6A",
    "native@0x40AB74",
    "native@0x40B51B",
    "native@0x40B534",
    "native@0x40B540",
    "native@0x40AB90",
    "native@0x40AB9E",
    "native@0x40ABA4",
    "native@0x40ABA8",
    "native@0x40B17F",
    "native@0x40B18D",
    "native@0x40B193",
    "native@0x40B197",
    "native@0x40ABAA",
    "native@0x40ABBD",
    "native@0x40ABC0",
    "native@0x40ABC4",
    "native@0x40ABE0",
    "native@0x40ABEE",
    "native@0x40ABF4",
    "native@0x40ABF8",
    "native@0x40B1D0",
    "native@0x40B1DE",
    "native@0x40B1E4",
    "native@0x40B1E8",
    "native@0x40ABFA",
    "native@0x40ABFF",
    "native@0x40AC19",
    "native@0x40AC31",
    "native@0x40AC3B",
    "native@0x40B542",
    "native@0x40B55F",
    "native@0x40B56B",
    "native@0x40AC56",
    "native@0x40AC64",
    "native@0x40AC6A",
    "native@0x40AC6E",
    "native@0x40B21C",
    "native@0x40B22A",
    "native@0x40B230",
    "native@0x40B234",
    "native@0x40AC70",
    "native@0x40AC81",
    "native@0x40AC9B",
    "native@0x40ACB3",
    "native@0x40ACBD",
    "native@0x40B56D",
    "native@0x40B58A",
    "native@0x40B596",
    "native@0x40ACD9",
    "native@0x40ACE7",
    "native@0x40ACED",
    "native@0x40ACF1",
    "native@0x40B26D",
    "native@0x40B27B",
    "native@0x40B281",
    "native@0x40B285",
    "native@0x40ACF3",
    "native@0x40AD06",
    "native@0x40AD18",
    "native@0x40AD1C",
    "native@0x40B598",
    "native@0x40B5AF",
    "native@0x40B5B5",
    "native@0x40AD38",
    "native@0x40AD46",
    "native@0x40AD4C",
    "native@0x40AD50",
    "native@0x40B2DB",
    "native@0x40B2E9",
    "native@0x40B2EF",
    "native@0x40B2F3",
    "native@0x40AD52",
    "native@0x40AD65",
    "native@0x40AD68",
    "native@0x40AD6C",
    "native@0x40AD88",
    "native@0x40AD96",
    "native@0x40AD9C",
    "native@0x40ADA0",
    "native@0x40B32C",
    "native@0x40B340",
    "native@0x40ADA2",
    "native@0x40ADB5",
    "native@0x40ADB8",
    "native@0x40ADBC",
    "native@0x40ADD8",
    "native@0x40ADE6",
    "native@0x40ADEC",
    "native@0x40ADF0",
    "native@0x40B37C",
    "native@0x40B38A",
    "native@0x40B390",
    "native@0x40B394",
    "native@0x40ADF2",
    "native@0x40AE05",
    "native@0x40AE08",
    "native@0x40AE18",
    "native@0x40A5CA",
    "native@0x40A5DC",
    "native@0x40A5DF",
    "native@0x40A5E3",
    "native@0x40AE3E",
    "native@0x40AE63",
    "native@0x40AE82",
    "native@0x40AE85",
    "native@0x40AE89",
    "native@0x40AEA5",
    "native@0x40AEC6",
    "native@0x40AEDA",
    "native@0x40AEE4",
    "native@0x40B5B7",
    "native@0x40B5D0",
    "native@0x40B5DC",
    "native@0x40AF00",
    "native@0x40AF1C",
    "native@0x40AF2F",
    "native@0x40AF9D",
    "native@0x40AFBB",
    "native@0x40AFD3",
    "native@0x40AFDD",
    "native@0x40B5DE",
    "native@0x40B5FB",
    "native@0x40B607",
    "native@0x40AFF9",
    "native@0x40B00C",
    "native@0x40B01E",
    "native@0x40B022",
    "native@0x40B609",
    "native@0x40B620",
    "native@0x40B626",
    "native@0x40B03E",
    "native@0x40B059",
    "native@0x40B06B",
    "native@0x40B06F",
    "native@0x40B628",
    "native@0x40B63F",
    "native@0x40B645",
    "native@0x40B08B",
    "native@0x40B094",
    "native@0x40B0B3",
    "native@0x40B0B6",
    "native@0x40B0BA",
    "native@0x40A792",
)


def _output_excerpt(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    lines = [line[:1_500] for line in (value or "").splitlines()]
    normalized = "\n".join(lines)
    if len(normalized) <= _FAILURE_OUTPUT_LIMIT:
        return normalized
    diagnostic = "\n".join(
        line
        for line in lines
        if any(
            marker in line
            for marker in (
                "Traceback",
                "Error",
                "Rejected",
                "failed",
                "Failure",
                "graph_closure",
                "native-body",
                "semantic validation",
                "GENERATED checksum",
                "rhad-generated",
            )
        )
    )
    head_limit = _FAILURE_OUTPUT_LIMIT // 2
    tail_limit = _FAILURE_OUTPUT_LIMIT - head_limit
    return (
        diagnostic[:head_limit]
        + "\n... failure output elided ...\n"
        + normalized[-tail_limit:]
    )


def _fixture() -> pathlib.Path:
    override = os.environ.get("D810_RHAD_LOADER_FIXTURE")
    return pathlib.Path(override).resolve() if override else _BINARY


def _instructions(block: object) -> tuple[object, ...]:
    rows = []
    instruction = block.head
    while instruction is not None:
        rows.append(instruction)
        if instruction is block.tail:
            break
        instruction = instruction.next
    return tuple(rows)


def _native_anchor(block: object, origins: dict[int, int]) -> int:
    return min(
        (
            int(origins.get(int(row.ea), int(row.ea)))
            for row in _instructions(block)
            if int(origins.get(int(row.ea), int(row.ea))) > 0
        ),
        default=int(block.start),
    )


def _route_snapshot(mba: object) -> dict[str, object]:
    import ida_hexrays

    from d810.hexrays.mutation.detached_handler_island import (
        imported_detached_snippet_instruction_origins,
    )

    origins = dict(imported_detached_snippet_instruction_origins(mba))
    blocks = {serial: mba.get_mblock(serial) for serial in range(int(mba.qty))}

    def exact_indirect(transfer_ea: int) -> bool:
        return any(
            int(row.opcode) == int(ida_hexrays.m_ijmp)
            and int(origins.get(int(row.ea), int(row.ea))) == int(transfer_ea)
            for block in blocks.values()
            for row in _instructions(block)
        )

    def source_at(anchor_ea: int) -> object | None:
        return next(
            (
                block
                for block in blocks.values()
                if any(
                    int(origins.get(int(row.ea), int(row.ea))) == int(anchor_ea)
                    for row in _instructions(block)
                )
            ),
            None,
        )

    def route_targets(
        source: object | None,
        corridor_anchor_eas: set[int],
    ) -> set[int]:
        if source is None:
            return set()
        targets: set[int] = set()
        source_successors = tuple(int(value) for value in source.succset)
        if source_successors:
            for successor_serial in source_successors:
                target = blocks[successor_serial]
                while (
                    _native_anchor(target, origins) in corridor_anchor_eas
                    and len(tuple(target.succset)) == 1
                ):
                    successor_serial = int(tuple(target.succset)[0])
                    target = blocks[successor_serial]
                targets.add(_native_anchor(target, origins))
            return targets
        corridor_blocks = [source]
        if source.nextb is not None:
            corridor_blocks.append(source.nextb)
            if source.nextb.nextb is not None:
                corridor_blocks.append(source.nextb.nextb)
        for block in corridor_blocks:
            if block.tail is None:
                continue
            opcode = int(block.tail.opcode)
            operand = (
                block.tail.l if opcode == int(ida_hexrays.m_goto) else block.tail.d
            )
            if int(operand.t) == int(ida_hexrays.mop_b):
                targets.add(_native_anchor(blocks[int(operand.b)], origins))
        return targets

    def reachable_anchors() -> tuple[int, ...]:
        reachable: set[int] = set()
        pending = [0]
        while pending:
            serial = pending.pop()
            if serial in reachable:
                continue
            reachable.add(serial)
            pending.extend(int(value) for value in blocks[serial].succset)
        return tuple(
            sorted({_native_anchor(blocks[serial], origins) for serial in reachable})
        )

    transfer_indirect = exact_indirect(0x40A605)
    source = source_at(0x40A5F0)
    row5_source = source_at(0x40A65D)
    row5_targets = route_targets(row5_source, {0x40A663})
    row5_snapshot = {
        "row5_source_present": row5_source is not None,
        "row5_indirect": exact_indirect(0x40A661),
        "row5_target_eas": tuple(sorted(row5_targets)),
    }
    row6_source = source_at(0x40A675)
    row6_live_targets = route_targets(row6_source, {0x40AE26})

    def row6_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AE26 <= int(live_anchor_ea) < 0x40AE3E:
            return 0x40AE26
        return int(live_anchor_ea)

    row6_snapshot = {
        "row6_source_present": row6_source is not None,
        "row6_indirect": exact_indirect(0x40A679),
        "row6_target_eas": tuple(
            sorted(row6_semantic_anchor(ea) for ea in row6_live_targets)
        ),
    }
    selected_source = source_at(0x40A692)
    selected_targets = route_targets(selected_source, {0x40A69A, 0x40A6A0})
    selected_snapshot = {
        "selected_source_present": selected_source is not None,
        "selected_indirect": exact_indirect(0x40A6A4),
        "selected_target_eas": tuple(sorted(selected_targets)),
    }
    row9_source = source_at(0x40A6AC)
    row9_targets = route_targets(row9_source, {0x40A6B4, 0x40A6BA})
    row9_snapshot = {
        "row9_source_present": row9_source is not None,
        "row9_indirect": exact_indirect(0x40A6BE),
        "row9_target_eas": tuple(sorted(row9_targets)),
    }
    row10_source = source_at(0x40A6C6)
    row10_targets = route_targets(row10_source, {0x40A6CE, 0x40A6D4})
    row10_snapshot = {
        "row10_source_present": row10_source is not None,
        "row10_indirect": exact_indirect(0x40A6D8),
        "row10_target_eas": tuple(sorted(row10_targets)),
    }
    row11_source = source_at(0x40A6E0)
    row11_targets = route_targets(row11_source, {0x40A6E8, 0x40A6EE})
    row11_snapshot = {
        "row11_source_present": row11_source is not None,
        "row11_indirect": exact_indirect(0x40A6F2),
        "row11_target_eas": tuple(sorted(row11_targets)),
    }
    row12_source = source_at(0x40A6FA)
    row12_targets = route_targets(row12_source, {0x40A702, 0x40A708})
    row12_snapshot = {
        "row12_source_present": row12_source is not None,
        "row12_indirect": exact_indirect(0x40A70C),
        "row12_target_eas": tuple(sorted(row12_targets)),
    }
    setcc_source = source_at(0x40A76E)
    setcc_live_targets = route_targets(setcc_source, set())

    def setcc_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A77E <= int(live_anchor_ea) < 0x40A794:
            return 0x40A77E
        if 0x40ABC6 <= int(live_anchor_ea) < 0x40ABE0:
            return 0x40ABC6
        if 0x40ABE0 <= int(live_anchor_ea) < 0x40ABFA:
            return 0x40ABC6
        if 0x40B1D0 <= int(live_anchor_ea) < 0x40B1EA:
            return 0x40ABC6
        return int(live_anchor_ea)

    setcc_snapshot = {
        "setcc_source_present": setcc_source is not None,
        "setcc_indirect": exact_indirect(0x40A77C),
        "setcc_target_eas": tuple(
            sorted(setcc_semantic_anchor(ea) for ea in setcc_live_targets)
        ),
    }
    scaled_setcc_source = source_at(0x40A786)
    scaled_setcc_live_targets = route_targets(scaled_setcc_source, set())

    def scaled_setcc_semantic_anchor(live_anchor_ea: int) -> int:
        if int(live_anchor_ea) in {0x40A5F0, 0x40A7AE}:
            return 0x40A794
        if 0x40A794 <= int(live_anchor_ea) < 0x40A7AE:
            return 0x40A794
        if 0x40AEE6 <= int(live_anchor_ea) < 0x40AF00:
            return 0x40AEE6
        return int(live_anchor_ea)

    scaled_setcc_snapshot = {
        "scaled_setcc_source_present": scaled_setcc_source is not None,
        "scaled_setcc_indirect": exact_indirect(0x40A792),
        "scaled_setcc_target_eas": tuple(
            sorted(scaled_setcc_semantic_anchor(ea) for ea in scaled_setcc_live_targets)
        ),
    }
    row18_source = source_at(0x40A79A)
    row18_live_targets = route_targets(row18_source, {0x40A7A2, 0x40A7A8})
    row18_snapshot = {
        "row18_source_present": row18_source is not None,
        "row18_indirect": exact_indirect(0x40A7AC),
        "row18_target_eas": tuple(sorted(row18_live_targets)),
    }
    row19_source = source_at(0x40A7E5)
    row19_live_targets = route_targets(row19_source, {0x40B6C0})

    def row19_semantic_anchor(live_anchor_ea: int) -> int | None:
        if int(live_anchor_ea) == 0x40A7E5:
            return None
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row19_snapshot = {
        "row19_source_present": row19_source is not None,
        "row19_indirect": exact_indirect(0x40A7EF),
        "row19_target_eas": tuple(
            sorted(
                anchor
                for ea in row19_live_targets
                if (anchor := row19_semantic_anchor(ea)) is not None
            )
        ),
    }
    row20_source = source_at(0x40A806)
    row20_live_targets = route_targets(row20_source, {0x40A80E, 0x40A814})
    row20_snapshot = {
        "row20_source_present": row20_source is not None,
        "row20_indirect": exact_indirect(0x40A818),
        "row20_target_eas": tuple(sorted(row20_live_targets)),
    }
    row21_source = source_at(0x40A820)
    row21_live_targets = route_targets(row21_source, {0x40A828, 0x40A82E})
    row21_snapshot = {
        "row21_source_present": row21_source is not None,
        "row21_indirect": exact_indirect(0x40A832),
        "row21_target_eas": tuple(sorted(row21_live_targets)),
    }
    row22_source = source_at(0x40A83A)
    row22_live_targets = route_targets(row22_source, {0x40A842, 0x40A848})
    row22_snapshot = {
        "row22_source_present": row22_source is not None,
        "row22_indirect": exact_indirect(0x40A84C),
        "row22_target_eas": tuple(sorted(row22_live_targets)),
    }
    row23_source = source_at(0x40A854)
    row23_live_targets = route_targets(row23_source, {0x40A85C, 0x40A862})

    def row23_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A868 <= int(live_anchor_ea) < 0x40A8A9:
            return 0x40A868
        return int(live_anchor_ea)

    row23_snapshot = {
        "row23_source_present": row23_source is not None,
        "row23_indirect": exact_indirect(0x40A866),
        "row23_target_eas": tuple(
            sorted(row23_semantic_anchor(ea) for ea in row23_live_targets)
        ),
    }
    row25_source = source_at(0x40A8A9)
    row25_live_targets = route_targets(row25_source, {0x40A64B})

    def row25_semantic_anchor(live_anchor_ea: int) -> int | None:
        if int(live_anchor_ea) == 0x40A8A9:
            return None
        if 0x40A64B <= int(live_anchor_ea) < 0x40A663:
            return 0x40A64B
        if 0x40AAF1 <= int(live_anchor_ea) < 0x40AAFD:
            return 0x40A64B
        return int(live_anchor_ea)

    row25_snapshot = {
        "row25_source_present": row25_source is not None,
        "row25_indirect": exact_indirect(0x40A8B3),
        "row25_target_eas": tuple(
            sorted(
                anchor
                for ea in row25_live_targets
                if (anchor := row25_semantic_anchor(ea)) is not None
            )
        ),
    }
    row26_source = source_at(0x40A8BB)
    row26_live_targets = route_targets(row26_source, {0x40A8C3, 0x40A8C9})
    row26_snapshot = {
        "row26_source_present": row26_source is not None,
        "row26_indirect": exact_indirect(0x40A8CD),
        "row26_target_eas": tuple(sorted(row26_live_targets)),
    }
    row27_source = source_at(0x40A8D5)
    row27_live_targets = route_targets(row27_source, {0x40A8DD, 0x40A8E3})
    row27_snapshot = {
        "row27_source_present": row27_source is not None,
        "row27_indirect": exact_indirect(0x40A8E7),
        "row27_target_eas": tuple(sorted(row27_live_targets)),
    }
    row28_source = source_at(0x40A8EF)
    row28_live_targets = route_targets(row28_source, {0x40A8F7, 0x40A8FD})

    def row28_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A903 <= int(live_anchor_ea) < 0x40A960:
            return 0x40A903
        if 0x40B4F0 <= int(live_anchor_ea) < 0x40B51B:
            return 0x40A903
        return int(live_anchor_ea)

    row28_snapshot = {
        "row28_source_present": row28_source is not None,
        "row28_indirect": exact_indirect(0x40A901),
        "row28_target_eas": tuple(
            sorted(row28_semantic_anchor(ea) for ea in row28_live_targets)
        ),
    }
    row29_source = source_at(0x40A954)
    row29_live_targets = route_targets(row29_source, {0x40B6C0})

    def row29_semantic_anchor(live_anchor_ea: int) -> int | None:
        if int(live_anchor_ea) == 0x40A954:
            return None
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row29_snapshot = {
        "row29_source_present": row29_source is not None,
        "row29_indirect": exact_indirect(0x40A95E),
        "row29_target_eas": tuple(
            sorted(
                anchor
                for ea in row29_live_targets
                if (anchor := row29_semantic_anchor(ea)) is not None
            )
        ),
    }
    row30_source = source_at(0x40A966)
    row30_live_targets = route_targets(row30_source, {0x40A96E, 0x40A974})

    def row30_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A97A <= int(live_anchor_ea) < 0x40A994:
            return 0x40A97A
        if 0x40AD1E <= int(live_anchor_ea) < 0x40AD38:
            return 0x40AD1E
        return int(live_anchor_ea)

    row30_snapshot = {
        "row30_source_present": row30_source is not None,
        "row30_indirect": exact_indirect(0x40A978),
        "row30_target_eas": tuple(
            sorted(row30_semantic_anchor(ea) for ea in row30_live_targets)
        ),
    }
    row31_source = source_at(0x40A980)
    row31_live_targets = route_targets(row31_source, {0x40A988, 0x40A98E})

    def row31_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A994 <= int(live_anchor_ea) < 0x40A9AE:
            return 0x40A994
        if 0x40B071 <= int(live_anchor_ea) < 0x40B08B:
            return 0x40B071
        return int(live_anchor_ea)

    row31_snapshot = {
        "row31_source_present": row31_source is not None,
        "row31_indirect": exact_indirect(0x40A992),
        "row31_target_eas": tuple(
            sorted(row31_semantic_anchor(ea) for ea in row31_live_targets)
        ),
    }
    row32_source = source_at(0x40A99A)
    row32_live_targets = route_targets(row32_source, {0x40A9A2, 0x40A9A8})

    def row32_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A9AE <= int(live_anchor_ea) < 0x40A9DE:
            return 0x40A9AE
        return int(live_anchor_ea)

    row32_snapshot = {
        "row32_source_present": row32_source is not None,
        "row32_indirect": exact_indirect(0x40A9AC),
        "row32_target_eas": tuple(
            sorted(row32_semantic_anchor(ea) for ea in row32_live_targets)
        ),
    }
    row33_source = source_at(0x40A9C7)
    row33_live_targets = route_targets(row33_source, {0x40A9D5, 0x40A9D8})

    def row33_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row33_snapshot = {
        "row33_source_present": row33_source is not None,
        "row33_indirect": exact_indirect(0x40A9DC),
        "row33_target_eas": tuple(
            sorted(row33_semantic_anchor(ea) for ea in row33_live_targets)
        ),
    }
    row34_source = source_at(0x40A9E4)
    row34_live_targets = route_targets(row34_source, {0x40A9EC, 0x40A9F2})

    def row34_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A9F8 <= int(live_anchor_ea) < 0x40AA12:
            return 0x40A9F8
        if 0x40AD6E <= int(live_anchor_ea) < 0x40AD88:
            return 0x40AD6E
        return int(live_anchor_ea)

    row34_snapshot = {
        "row34_source_present": row34_source is not None,
        "row34_indirect": exact_indirect(0x40A9F6),
        "row34_target_eas": tuple(
            sorted(row34_semantic_anchor(ea) for ea in row34_live_targets)
        ),
    }
    row35_source = source_at(0x40A9FE)
    row35_live_targets = route_targets(row35_source, {0x40AA06, 0x40AA0C})

    def row35_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AA12 <= int(live_anchor_ea) < 0x40AA2C:
            return 0x40AA12
        if 0x40B0BC <= int(live_anchor_ea) < 0x40B0D6:
            return 0x40B0BC
        return int(live_anchor_ea)

    row35_snapshot = {
        "row35_source_present": row35_source is not None,
        "row35_indirect": exact_indirect(0x40AA10),
        "row35_target_eas": tuple(
            sorted(row35_semantic_anchor(ea) for ea in row35_live_targets)
        ),
    }
    row36_source = source_at(0x40AA18)
    row36_live_targets = route_targets(row36_source, {0x40AA20, 0x40AA26})

    def row36_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AA2C <= int(live_anchor_ea) < 0x40AA60:
            return 0x40AA2C
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        return int(live_anchor_ea)

    row36_snapshot = {
        "row36_source_present": row36_source is not None,
        "row36_indirect": exact_indirect(0x40AA2A),
        "row36_target_eas": tuple(
            sorted(row36_semantic_anchor(ea) for ea in row36_live_targets)
        ),
    }
    row37_source = source_at(0x40AA49)
    row37_live_targets = route_targets(row37_source, {0x40AA57, 0x40AA5A})

    def row37_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row37_snapshot = {
        "row37_source_present": row37_source is not None,
        "row37_indirect": exact_indirect(0x40AA5E),
        "row37_target_eas": tuple(
            sorted(row37_semantic_anchor(ea) for ea in row37_live_targets)
        ),
    }
    row38_source = source_at(0x40AA66)
    row38_live_targets = route_targets(row38_source, {0x40AA6E, 0x40AA74})

    def row38_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AA7A <= int(live_anchor_ea) < 0x40AA94:
            return 0x40AA7A
        if 0x40ADBE <= int(live_anchor_ea) < 0x40ADD8:
            return 0x40ADBE
        return int(live_anchor_ea)

    row38_snapshot = {
        "row38_source_present": row38_source is not None,
        "row38_indirect": exact_indirect(0x40AA78),
        "row38_target_eas": tuple(
            sorted(row38_semantic_anchor(ea) for ea in row38_live_targets)
        ),
    }
    row39_source = source_at(0x40AA80)
    row39_live_targets = route_targets(row39_source, {0x40AA88, 0x40AA8E})

    def row39_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AAA2 <= int(live_anchor_ea) < 0x40AAAE:
            return 0x40AA94
        if 0x40B0F2 <= int(live_anchor_ea) < 0x40B10C:
            return 0x40B0F2
        return int(live_anchor_ea)

    row39_snapshot = {
        "row39_source_present": row39_source is not None,
        "row39_indirect": exact_indirect(0x40AA92),
        "row39_target_eas": tuple(
            sorted(row39_semantic_anchor(ea) for ea in row39_live_targets)
        ),
    }
    row40_source = source_at(0x40AA9A)
    row40_live_targets = route_targets(row40_source, {0x40AAA2, 0x40AAA8})

    def row40_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AAAE <= int(live_anchor_ea) < 0x40AAF1:
            return 0x40AAAE
        return int(live_anchor_ea)

    row40_snapshot = {
        "row40_source_present": row40_source is not None,
        "row40_indirect": exact_indirect(0x40AAAC),
        "row40_target_eas": tuple(
            sorted(row40_semantic_anchor(ea) for ea in row40_live_targets)
        ),
    }
    row42_source = source_at(0x40AAF1)
    row42_live_targets = route_targets(row42_source, set())
    row42_snapshot = {
        "row42_source_present": row42_source is not None,
        "row42_indirect": exact_indirect(0x40AAFB),
        "row42_target_eas": tuple(
            sorted(
                0x40AAFD if 0x40AAFD <= ea < 0x40AB17 else ea
                for ea in row42_live_targets
            )
        ),
    }
    row43_source = source_at(0x40AB03)
    row43_live_targets = route_targets(row43_source, {0x40AB0B, 0x40AB11})

    def row43_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AB17 <= int(live_anchor_ea) < 0x40AB31:
            return 0x40AB17
        if 0x40B149 <= int(live_anchor_ea) < 0x40B163:
            return 0x40B149
        return int(live_anchor_ea)

    row43_snapshot = {
        "row43_source_present": row43_source is not None,
        "row43_indirect": exact_indirect(0x40AB15),
        "row43_target_eas": tuple(
            sorted(row43_semantic_anchor(ea) for ea in row43_live_targets)
        ),
    }
    row44_source = source_at(0x40AB1D)
    row44_live_targets = route_targets(row44_source, {0x40AB25, 0x40AB2B})

    def row44_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AB31 <= int(live_anchor_ea) < 0x40AB76:
            return 0x40AB31
        return int(live_anchor_ea)

    row44_snapshot = {
        "row44_source_present": row44_source is not None,
        "row44_indirect": exact_indirect(0x40AB2F),
        "row44_target_eas": tuple(
            sorted(row44_semantic_anchor(ea) for ea in row44_live_targets)
        ),
    }
    row45_source = source_at(0x40AB6A)
    row45_live_targets = route_targets(row45_source, set())
    row45_snapshot = {
        "row45_source_present": row45_source is not None,
        "row45_indirect": exact_indirect(0x40AB74),
        "row45_target_eas": tuple(sorted(row45_live_targets)),
    }
    row46_source = source_at(0x40AB7C)
    row46_live_targets = route_targets(row46_source, {0x40AB84, 0x40AB8A})

    def row46_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AB90 <= int(live_anchor_ea) < 0x40ABAA:
            return 0x40AB90
        if 0x40B17F <= int(live_anchor_ea) < 0x40B199:
            return 0x40B17F
        return int(live_anchor_ea)

    row46_snapshot = {
        "row46_source_present": row46_source is not None,
        "row46_indirect": exact_indirect(0x40AB8E),
        "row46_target_eas": tuple(
            sorted(row46_semantic_anchor(ea) for ea in row46_live_targets)
        ),
    }
    row47_source = source_at(0x40AB96)
    row47_live_targets = route_targets(row47_source, {0x40AB9E, 0x40ABA4})

    def row47_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40ABAA <= int(live_anchor_ea) < 0x40ABC6:
            return 0x40ABAA
        return int(live_anchor_ea)

    row47_snapshot = {
        "row47_source_present": row47_source is not None,
        "row47_indirect": exact_indirect(0x40ABA8),
        "row47_target_eas": tuple(
            sorted(row47_semantic_anchor(ea) for ea in row47_live_targets)
        ),
    }
    row49_source = source_at(0x40ABCC)
    row49_live_targets = route_targets(row49_source, {0x40ABD4, 0x40ABDA})

    def row49_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40ABE0 <= int(live_anchor_ea) < 0x40ABFA:
            return 0x40ABE0
        if 0x40B1D0 <= int(live_anchor_ea) < 0x40B1EA:
            return 0x40B1D0
        return int(live_anchor_ea)

    row49_snapshot = {
        "row49_source_present": row49_source is not None,
        "row49_indirect": exact_indirect(0x40ABDE),
        "row49_target_eas": tuple(
            sorted(row49_semantic_anchor(ea) for ea in row49_live_targets)
        ),
    }
    row50_source = source_at(0x40ABE6)
    row50_live_targets = route_targets(row50_source, {0x40ABEE, 0x40ABF4})

    def row50_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40ABFA <= int(live_anchor_ea) < 0x40AC3D:
            return 0x40ABFA
        if 0x40B542 <= int(live_anchor_ea) < 0x40B56D:
            return 0x40ABFA
        return int(live_anchor_ea)

    row50_snapshot = {
        "row50_source_present": row50_source is not None,
        "row50_indirect": exact_indirect(0x40ABF8),
        "row50_target_eas": tuple(
            sorted(row50_semantic_anchor(ea) for ea in row50_live_targets)
        ),
    }
    row51_source = source_at(0x40AC31)
    row51_live_targets = route_targets(row51_source, set())
    row51_snapshot = {
        "row51_source_present": row51_source is not None,
        "row51_indirect": exact_indirect(0x40AC3B),
        "row51_target_eas": tuple(sorted(row51_live_targets)),
    }
    row52_source = source_at(0x40AC42)
    row52_live_targets = route_targets(row52_source, {0x40AC4A, 0x40AC50})

    def row52_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AC56 <= int(live_anchor_ea) < 0x40AC70:
            return 0x40AC56
        if 0x40B21C <= int(live_anchor_ea) < 0x40B236:
            return 0x40B21C
        return int(live_anchor_ea)

    row52_snapshot = {
        "row52_source_present": row52_source is not None,
        "row52_indirect": exact_indirect(0x40AC54),
        "row52_target_eas": tuple(
            sorted(row52_semantic_anchor(ea) for ea in row52_live_targets)
        ),
    }
    row53_source = source_at(0x40AC5C)
    row53_live_targets = route_targets(row53_source, {0x40AC64, 0x40AC6A})

    def row53_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AC70 <= int(live_anchor_ea) < 0x40ACBF:
            return 0x40AC70
        if 0x40B56D <= int(live_anchor_ea) < 0x40B598:
            return 0x40AC70
        return int(live_anchor_ea)

    row53_snapshot = {
        "row53_source_present": row53_source is not None,
        "row53_indirect": exact_indirect(0x40AC6E),
        "row53_target_eas": tuple(
            sorted(row53_semantic_anchor(ea) for ea in row53_live_targets)
        ),
    }
    row54_source = source_at(0x40ACB3)
    row54_live_targets = route_targets(row54_source, set())
    row54_snapshot = {
        "row54_source_present": row54_source is not None,
        "row54_indirect": exact_indirect(0x40ACBD),
        "row54_target_eas": tuple(sorted(row54_live_targets)),
    }
    row55_source = source_at(0x40ACC5)
    row55_live_targets = route_targets(row55_source, {0x40ACCD, 0x40ACD3})

    def row55_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40ACD9 <= int(live_anchor_ea) < 0x40ACF3:
            return 0x40ACD9
        if 0x40B26D <= int(live_anchor_ea) < 0x40B287:
            return 0x40B26D
        return int(live_anchor_ea)

    row55_snapshot = {
        "row55_source_present": row55_source is not None,
        "row55_indirect": exact_indirect(0x40ACD7),
        "row55_target_eas": tuple(
            sorted(row55_semantic_anchor(ea) for ea in row55_live_targets)
        ),
    }
    row56_source = source_at(0x40ACDF)
    row56_live_targets = route_targets(row56_source, {0x40ACE7, 0x40ACED})

    def row56_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40ACF3 <= int(live_anchor_ea) < 0x40AD1E:
            return 0x40ACF3
        if 0x40B598 <= int(live_anchor_ea) < 0x40B5B7:
            return 0x40ACF3
        return int(live_anchor_ea)

    row56_snapshot = {
        "row56_source_present": row56_source is not None,
        "row56_indirect": exact_indirect(0x40ACF1),
        "row56_target_eas": tuple(
            sorted(row56_semantic_anchor(ea) for ea in row56_live_targets)
        ),
    }
    row57_source = source_at(0x40AD18)
    row57_live_targets = route_targets(row57_source, set())
    row57_snapshot = {
        "row57_source_present": row57_source is not None,
        "row57_indirect": exact_indirect(0x40AD1C),
        "row57_target_eas": tuple(sorted(row57_live_targets)),
    }
    row58_source = source_at(0x40AD24)
    row58_live_targets = route_targets(row58_source, {0x40AD2C, 0x40AD32})

    def row58_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AD38 <= int(live_anchor_ea) < 0x40AD52:
            return 0x40AD38
        if 0x40B2DB <= int(live_anchor_ea) < 0x40B2F5:
            return 0x40B2DB
        return int(live_anchor_ea)

    row58_snapshot = {
        "row58_source_present": row58_source is not None,
        "row58_indirect": exact_indirect(0x40AD36),
        "row58_target_eas": tuple(
            sorted(row58_semantic_anchor(ea) for ea in row58_live_targets)
        ),
    }
    row59_source = source_at(0x40AD3E)
    row59_live_targets = route_targets(row59_source, {0x40AD46, 0x40AD4C})

    def row59_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AD52 <= int(live_anchor_ea) < 0x40AD6E:
            return 0x40AD52
        return int(live_anchor_ea)

    row59_snapshot = {
        "row59_source_present": row59_source is not None,
        "row59_indirect": exact_indirect(0x40AD50),
        "row59_target_eas": tuple(
            sorted(row59_semantic_anchor(ea) for ea in row59_live_targets)
        ),
    }
    row60_source = source_at(0x40AD57)
    row60_live_targets = route_targets(row60_source, {0x40AD65, 0x40AD68})

    def row60_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row60_snapshot = {
        "row60_source_present": row60_source is not None,
        "row60_indirect": exact_indirect(0x40AD6C),
        "row60_target_eas": tuple(
            sorted(row60_semantic_anchor(ea) for ea in row60_live_targets)
        ),
    }
    row61_source = source_at(0x40AD74)
    row61_live_targets = route_targets(row61_source, {0x40AD7C, 0x40AD82})

    def row61_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40AD88 <= int(live_anchor_ea) < 0x40ADA2:
            return 0x40AD88
        if 0x40B32C <= int(live_anchor_ea) < 0x40B342:
            return 0x40B32C
        return int(live_anchor_ea)

    row61_snapshot = {
        "row61_source_present": row61_source is not None,
        "row61_indirect": exact_indirect(0x40AD86),
        "row61_target_eas": tuple(
            sorted(row61_semantic_anchor(ea) for ea in row61_live_targets)
        ),
    }
    row62_source = source_at(0x40AD8E)
    row62_live_targets = route_targets(row62_source, {0x40AD96, 0x40AD9C})

    def row62_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40ADA2 <= int(live_anchor_ea) < 0x40ADBE:
            return 0x40ADA2
        return int(live_anchor_ea)

    row62_snapshot = {
        "row62_source_present": row62_source is not None,
        "row62_indirect": exact_indirect(0x40ADA0),
        "row62_target_eas": tuple(
            sorted(row62_semantic_anchor(ea) for ea in row62_live_targets)
        ),
    }
    row63_source = source_at(0x40ADA7)
    row63_live_targets = route_targets(row63_source, {0x40ADB5, 0x40ADB8})

    def row63_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row63_snapshot = {
        "row63_source_present": row63_source is not None,
        "row63_indirect": exact_indirect(0x40ADBC),
        "row63_target_eas": tuple(
            sorted(row63_semantic_anchor(ea) for ea in row63_live_targets)
        ),
    }
    row64_source = source_at(0x40ADC4)
    row64_live_targets = route_targets(row64_source, {0x40ADCC, 0x40ADD2})

    def row64_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40ADD8 <= int(live_anchor_ea) < 0x40ADF2:
            return 0x40ADD8
        if 0x40B37C <= int(live_anchor_ea) < 0x40B396:
            return 0x40B37C
        return int(live_anchor_ea)

    row64_snapshot = {
        "row64_source_present": row64_source is not None,
        "row64_indirect": exact_indirect(0x40ADD6),
        "row64_target_eas": tuple(
            sorted(row64_semantic_anchor(ea) for ea in row64_live_targets)
        ),
    }
    row65_source = source_at(0x40ADDE)
    row65_live_targets = route_targets(row65_source, {0x40ADE6, 0x40ADEC})

    def row65_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40ADF2 <= int(live_anchor_ea) < 0x40AE1A:
            return 0x40ADF2
        return int(live_anchor_ea)

    row65_snapshot = {
        "row65_source_present": row65_source is not None,
        "row65_indirect": exact_indirect(0x40ADF0),
        "row65_target_eas": tuple(
            sorted(row65_semantic_anchor(ea) for ea in row65_live_targets)
        ),
    }
    row66_source = source_at(0x40ADF7)
    row66_live_targets = route_targets(row66_source, {0x40AE05, 0x40AE08})

    def row66_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row66_snapshot = {
        "row66_source_present": row66_source is not None,
        "row66_indirect": exact_indirect(0x40AE18),
        "row66_target_eas": tuple(
            sorted(row66_semantic_anchor(ea) for ea in row66_live_targets)
        ),
    }
    row67_source = source_at(0x40AE1A)
    row67_live_targets = route_targets(row67_source, set())

    def row67_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5CA <= int(live_anchor_ea) < 0x40A5E5:
            return 0x40A5CA
        return int(live_anchor_ea)

    row67_snapshot = {
        "row67_source_present": row67_source is not None,
        "row67_indirect": exact_indirect(0x40AE24),
        "row67_target_eas": tuple(
            sorted(row67_semantic_anchor(ea) for ea in row67_live_targets)
        ),
    }
    row68_source = source_at(0x40AE28)
    row68_live_targets = route_targets(row68_source, {0x40A560})

    def row68_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AE3E <= int(live_anchor_ea) < 0x40AE8B:
            return 0x40AE3E
        return int(live_anchor_ea)

    row68_snapshot = {
        "row68_source_present": row68_source is not None,
        "row68_indirect": exact_indirect(0x40AE3C),
        "row68_target_eas": tuple(
            sorted(row68_semantic_anchor(ea) for ea in row68_live_targets)
        ),
    }
    row69_source = source_at(0x40AE74)
    row69_live_targets = route_targets(row69_source, {0x40AE82, 0x40AE85})

    def row69_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row69_snapshot = {
        "row69_source_present": row69_source is not None,
        "row69_indirect": exact_indirect(0x40AE89),
        "row69_target_eas": tuple(
            sorted(row69_semantic_anchor(ea) for ea in row69_live_targets)
        ),
    }
    row70_source = source_at(0x40AE91)
    row70_live_targets = route_targets(row70_source, {0x40AE99, 0x40AE9F})

    def row70_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AEA5 <= int(live_anchor_ea) < 0x40AEE6:
            return 0x40AEA5
        return int(live_anchor_ea)

    row70_snapshot = {
        "row70_source_present": row70_source is not None,
        "row70_indirect": exact_indirect(0x40AEA3),
        "row70_target_eas": tuple(
            sorted(row70_semantic_anchor(ea) for ea in row70_live_targets)
        ),
    }
    row71_source = source_at(0x40AEDA)
    row71_live_targets = route_targets(row71_source, set())

    def row71_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row71_snapshot = {
        "row71_source_present": row71_source is not None,
        "row71_indirect": exact_indirect(0x40AEE4),
        "row71_target_eas": tuple(
            sorted(row71_semantic_anchor(ea) for ea in row71_live_targets)
        ),
    }
    row72_source = source_at(0x40AEEC)
    row72_live_targets = route_targets(row72_source, {0x40AEF4, 0x40AEFA})

    def row72_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AF00 <= int(live_anchor_ea) < 0x40AFDF:
            return 0x40AF00
        return int(live_anchor_ea)

    row72_snapshot = {
        "row72_source_present": row72_source is not None,
        "row72_indirect": exact_indirect(0x40AEFE),
        "row72_target_eas": tuple(
            sorted(row72_semantic_anchor(ea) for ea in row72_live_targets)
        ),
    }
    row73_source = source_at(0x40AFD3)
    row73_live_targets = route_targets(row73_source, set())

    def row73_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row73_snapshot = {
        "row73_source_present": row73_source is not None,
        "row73_indirect": exact_indirect(0x40AFDD),
        "row73_target_eas": tuple(
            sorted(row73_semantic_anchor(ea) for ea in row73_live_targets)
        ),
    }
    row74_source = source_at(0x40AFE5)
    row74_live_targets = route_targets(row74_source, {0x40AFED, 0x40AFF3})

    def row74_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40AFF9 <= int(live_anchor_ea) < 0x40B024:
            return 0x40AFF9
        return int(live_anchor_ea)

    row74_snapshot = {
        "row74_source_present": row74_source is not None,
        "row74_indirect": exact_indirect(0x40AFF7),
        "row74_target_eas": tuple(
            sorted(row74_semantic_anchor(ea) for ea in row74_live_targets)
        ),
    }
    row75_source = source_at(0x40B01E)
    row75_live_targets = route_targets(row75_source, set())

    def row75_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row75_snapshot = {
        "row75_source_present": row75_source is not None,
        "row75_indirect": exact_indirect(0x40B022),
        "row75_target_eas": tuple(
            sorted(row75_semantic_anchor(ea) for ea in row75_live_targets)
        ),
    }
    row76_source = source_at(0x40B02A)
    row76_live_targets = route_targets(row76_source, {0x40B032, 0x40B038})

    def row76_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40B03E <= int(live_anchor_ea) < 0x40B071:
            return 0x40B03E
        if 0x40B628 <= int(live_anchor_ea) < 0x40B647:
            return 0x40B03E
        return int(live_anchor_ea)

    row76_snapshot = {
        "row76_source_present": row76_source is not None,
        "row76_indirect": exact_indirect(0x40B03C),
        "row76_target_eas": tuple(
            sorted(row76_semantic_anchor(ea) for ea in row76_live_targets)
        ),
    }
    row77_source = source_at(0x40B06B)
    row77_live_targets = route_targets(row77_source, set())

    def row77_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row77_snapshot = {
        "row77_source_present": row77_source is not None,
        "row77_indirect": exact_indirect(0x40B06F),
        "row77_target_eas": tuple(
            sorted(row77_semantic_anchor(ea) for ea in row77_live_targets)
        ),
    }
    row78_source = source_at(0x40B077)
    row78_live_targets = route_targets(row78_source, {0x40B07F, 0x40B085})

    def row78_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A5F0 <= int(live_anchor_ea) < 0x40A607:
            return 0x40A5F0
        if 0x40B08B <= int(live_anchor_ea) < 0x40B0BC:
            return 0x40B08B
        return int(live_anchor_ea)

    row78_snapshot = {
        "row78_source_present": row78_source is not None,
        "row78_indirect": exact_indirect(0x40B089),
        "row78_target_eas": tuple(
            sorted(row78_semantic_anchor(ea) for ea in row78_live_targets)
        ),
    }
    row79_source = source_at(0x40B0A5)
    row79_live_targets = route_targets(row79_source, {0x40B0B3, 0x40B0B6})

    def row79_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A607 <= int(live_anchor_ea) < 0x40A61B:
            return 0x40A607
        if 0x40B6C0 <= int(live_anchor_ea) < 0x40B6D6:
            return 0x40B6C0
        return int(live_anchor_ea)

    row79_snapshot = {
        "row79_source_present": row79_source is not None,
        "row79_indirect": exact_indirect(0x40B0BA),
        "row79_target_eas": tuple(
            sorted(row79_semantic_anchor(ea) for ea in row79_live_targets)
        ),
    }
    if source is None:
        return {
            "maturity": int(mba.maturity),
            "quantity": int(mba.qty),
            "source_present": False,
            "indirect": transfer_indirect,
            "target_eas": (),
            "reachable_eas": reachable_anchors(),
            **row5_snapshot,
            **row6_snapshot,
            **selected_snapshot,
            **row9_snapshot,
            **row10_snapshot,
            **row11_snapshot,
            **row12_snapshot,
            **setcc_snapshot,
            **scaled_setcc_snapshot,
            **row18_snapshot,
            **row19_snapshot,
            **row20_snapshot,
            **row21_snapshot,
            **row22_snapshot,
            **row23_snapshot,
            **row25_snapshot,
            **row26_snapshot,
            **row27_snapshot,
            **row28_snapshot,
            **row29_snapshot,
            **row30_snapshot,
            **row31_snapshot,
            **row32_snapshot,
            **row33_snapshot,
            **row34_snapshot,
            **row35_snapshot,
            **row36_snapshot,
            **row37_snapshot,
            **row38_snapshot,
            **row39_snapshot,
            **row40_snapshot,
            **row42_snapshot,
            **row43_snapshot,
            **row44_snapshot,
            **row45_snapshot,
            **row46_snapshot,
            **row47_snapshot,
            **row49_snapshot,
            **row50_snapshot,
            **row51_snapshot,
            **row52_snapshot,
            **row53_snapshot,
            **row54_snapshot,
            **row55_snapshot,
            **row56_snapshot,
            **row57_snapshot,
            **row58_snapshot,
            **row59_snapshot,
            **row60_snapshot,
            **row61_snapshot,
            **row62_snapshot,
            **row63_snapshot,
            **row64_snapshot,
            **row65_snapshot,
            **row66_snapshot,
            **row67_snapshot,
            **row68_snapshot,
            **row69_snapshot,
            **row70_snapshot,
            **row71_snapshot,
            **row72_snapshot,
            **row73_snapshot,
            **row74_snapshot,
            **row75_snapshot,
            **row76_snapshot,
            **row77_snapshot,
            **row78_snapshot,
            **row79_snapshot,
        }
    target_eas: set[int] = set()
    indirect = False
    source_successors = tuple(int(value) for value in source.succset)
    if source_successors:
        route_serials = [int(source.serial)]
        for successor_serial in source_successors:
            target = blocks[successor_serial]
            route_serials.append(successor_serial)
            while (
                _native_anchor(target, origins) in {0x40A5FE, 0x40A601}
                and len(tuple(target.succset)) == 1
            ):
                successor_serial = int(tuple(target.succset)[0])
                target = blocks[successor_serial]
                route_serials.append(successor_serial)
            target_eas.add(_native_anchor(target, origins))
        indirect = any(
            block.tail is not None and int(block.tail.opcode) == int(ida_hexrays.m_ijmp)
            for block in (blocks[serial] for serial in route_serials)
        )
    else:
        route_rows = (
            *(_instructions(source)[-1:]),
            *(_instructions(source.nextb)[-1:]),
            *(_instructions(source.nextb.nextb)[-1:]),
        )
        for row in route_rows:
            opcode = int(row.opcode)
            if opcode == int(ida_hexrays.m_ijmp):
                indirect = True
            operand = row.l if opcode == int(ida_hexrays.m_goto) else row.d
            if int(operand.t) != int(ida_hexrays.mop_b):
                continue
            target = blocks[int(operand.b)]
            target_eas.add(_native_anchor(target, origins))
    return {
        "maturity": int(mba.maturity),
        "quantity": int(mba.qty),
        "source_present": True,
        "source_serial": int(source.serial),
        "route_blocks": tuple(
            (
                int(block.serial),
                _native_anchor(block, origins),
                int(block.type),
                tuple(int(value) for value in block.succset),
            )
            for block in (source, source.nextb, source.nextb.nextb)
        ),
        "indirect": indirect,
        "target_eas": tuple(sorted(target_eas)),
        "reachable_eas": reachable_anchors(),
        **row5_snapshot,
        **row6_snapshot,
        **selected_snapshot,
        **row9_snapshot,
        **row10_snapshot,
        **row11_snapshot,
        **row12_snapshot,
        **setcc_snapshot,
        **scaled_setcc_snapshot,
        **row18_snapshot,
        **row19_snapshot,
        **row20_snapshot,
        **row21_snapshot,
        **row22_snapshot,
        **row23_snapshot,
        **row25_snapshot,
        **row26_snapshot,
        **row27_snapshot,
        **row28_snapshot,
        **row29_snapshot,
        **row30_snapshot,
        **row31_snapshot,
        **row32_snapshot,
        **row33_snapshot,
        **row34_snapshot,
        **row35_snapshot,
        **row36_snapshot,
        **row37_snapshot,
        **row38_snapshot,
        **row39_snapshot,
        **row40_snapshot,
        **row42_snapshot,
        **row43_snapshot,
        **row44_snapshot,
        **row45_snapshot,
        **row46_snapshot,
        **row47_snapshot,
        **row49_snapshot,
        **row50_snapshot,
        **row51_snapshot,
        **row52_snapshot,
        **row53_snapshot,
        **row54_snapshot,
        **row55_snapshot,
        **row56_snapshot,
        **row57_snapshot,
        **row58_snapshot,
        **row59_snapshot,
        **row60_snapshot,
        **row61_snapshot,
        **row62_snapshot,
        **row63_snapshot,
        **row64_snapshot,
        **row65_snapshot,
        **row66_snapshot,
        **row67_snapshot,
        **row68_snapshot,
        **row69_snapshot,
        **row70_snapshot,
        **row71_snapshot,
        **row72_snapshot,
        **row73_snapshot,
        **row74_snapshot,
        **row75_snapshot,
        **row76_snapshot,
        **row77_snapshot,
        **row78_snapshot,
        **row79_snapshot,
    }


def _run_worker(binary: pathlib.Path) -> None:
    faulthandler.dump_traceback_later(45, repeat=False)
    print("checksum-worker:open", flush=True)
    assert idapro.open_database(str(binary), True) == 0
    hook = None
    try:
        import ida_hexrays
        import idaapi
        import idc

        idaapi.auto_wait()
        assert ida_hexrays.init_hexrays_plugin()
        assert idc.SetType(0x40F830, "int __cdecl sub_40F830(void)")

        import d810.headless as headless

        headless.configure(
            project="default_unflattening_ollvm.json",
            ida_user_dir=binary.parent / "ida-user",
        )
        headless.start()

        class NoFlowRules:
            def get_active_rules(self, **_kwargs):
                return ()

        # The checksum isolates the GENERATED producer.  Retain the configured
        # instruction optimizer (its first callback owns the GENERATED seam),
        # while suppressing the older broad PREOPT flow publication entirely.
        headless._state.manager.block_optimizer._rule_scope_service = NoFlowRules()
        print("checksum-worker:started", flush=True)
        receipts = []
        from d810.hexrays.mutation.mba_mutation_events import MbaMutationCommitted

        headless._state.manager.event_emitter.on(
            MbaMutationCommitted,
            lambda event: receipts.append(event.receipt),
        )
        captures: dict[str, object] = {"calls_count": 0}

        class Probe(ida_hexrays.Hexrays_Hooks):
            def preoptimized(self, mba):
                if int(mba.entry_ea) == _FUNCTION_EA:
                    captures["preopt"] = _route_snapshot(mba)
                return 0

            def locopt(self, mba):
                if int(mba.entry_ea) == _FUNCTION_EA and "first_cfg" not in captures:
                    captures["first_cfg"] = _route_snapshot(mba)
                return 0

            def calls_done(self, mba):
                if int(mba.entry_ea) == _FUNCTION_EA:
                    captures["calls_count"] = int(captures["calls_count"]) + 1
                    captures["calls"] = _route_snapshot(mba)
                return 0

        hook = Probe()
        assert hook.hook()
        ida_hexrays.mark_cfunc_dirty(_FUNCTION_EA)
        print("checksum-worker:decompile", flush=True)
        failure = ida_hexrays.hexrays_failure_t()
        cfunc = headless.decompile(_FUNCTION_EA, failure=failure)
        print("checksum-worker:decompiled", flush=True)
        assert cfunc is not None, (
            f"A560 ctree failed: code={int(failure.code)} "
            f"ea=0x{int(failure.errea):X} desc={failure.desc()}"
        )
        matching = tuple(
            receipt
            for receipt in receipts
            if str(receipt.fragment_plan_id).startswith(
                "rhad-reference-compiler:rhad-generated-reference@0x40A560:"
            )
        )
        assert len(matching) == 1, tuple(
            str(receipt.fragment_plan_id) for receipt in receipts
        )
        receipt = matching[0]
        assert receipt.operation_count == receipt.planned_operation_count == 560, (
            receipt.operation_count,
            receipt.planned_operation_count,
        )
        assert len(receipt.version_transitions) >= 10
        assert receipt.prepublication_validation.passed
        assert receipt.postpublication_validation.passed
        assert receipt.root_publication_confirmed
        assert captures["preopt"]["indirect"] is False
        assert set(captures["preopt"]["target_eas"]) == {0x40A607, 0x40B6C0}, captures[
            "preopt"
        ]
        assert captures["first_cfg"]["indirect"] is False
        assert set(captures["first_cfg"]["target_eas"]) == {
            0x40A607,
            0x40B6C0,
        }, captures["first_cfg"]
        assert 0x40B6C0 in captures["first_cfg"]["reachable_eas"], captures["first_cfg"]
        for capture_name in ("preopt", "first_cfg"):
            selected_capture = captures[capture_name]
            assert selected_capture["row5_source_present"] is True
            assert selected_capture["row5_indirect"] is False
            assert set(selected_capture["row5_target_eas"]) == {
                0x40A663,
                *({0x40AAFD} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row5_target_eas"])
            assert selected_capture["row6_source_present"] is True
            assert selected_capture["row6_indirect"] is False
            assert set(selected_capture["row6_target_eas"]) == {
                0x40AE26,
                *({0x40A5CA} if capture_name == "preopt" else set()),
            }, selected_capture
            assert selected_capture["selected_source_present"] is True
            assert selected_capture["selected_indirect"] is False
            assert set(selected_capture["selected_target_eas"]) == {
                0x40A6A6,
                0x40A800,
            }, selected_capture
            assert selected_capture["row9_source_present"] is True
            assert selected_capture["row9_indirect"] is False
            assert set(selected_capture["row9_target_eas"]) == {
                0x40A6C0,
                0x40A960,
            }, selected_capture
            assert selected_capture["row10_source_present"] is True
            assert selected_capture["row10_indirect"] is False
            assert set(selected_capture["row10_target_eas"]) == {
                0x40A6DA,
                0x40AB76,
            }, selected_capture
            assert selected_capture["row11_source_present"] is True
            assert selected_capture["row11_indirect"] is False
            assert set(selected_capture["row11_target_eas"]) == {
                0x40A6F4,
                0x40AE8B,
            }, selected_capture
            assert selected_capture["row12_source_present"] is True
            assert selected_capture["row12_indirect"] is False
            assert set(selected_capture["row12_target_eas"]) == {
                0x40A5F0,
                {
                    "preopt": 0x40A70E,
                    "first_cfg": 0x40A71D,
                }[capture_name],
            }, selected_capture
            assert selected_capture["setcc_source_present"] is True
            assert selected_capture["setcc_indirect"] is False
            assert set(selected_capture["setcc_target_eas"]) == {
                0x40A77E,
                0x40ABC6,
            }, selected_capture
            assert selected_capture["scaled_setcc_source_present"] is True
            assert selected_capture["scaled_setcc_indirect"] is False
            assert set(selected_capture["scaled_setcc_target_eas"]) == {
                0x40A794,
                0x40AEE6,
            }, selected_capture
            assert selected_capture["row18_source_present"] is True
            assert selected_capture["row18_indirect"] is False
            assert set(selected_capture["row18_target_eas"]) == {
                0x40A5F0,
                0x40A7AE,
            }, selected_capture
            assert selected_capture["row19_source_present"] is True
            assert selected_capture["row19_indirect"] is False
            assert set(selected_capture["row19_target_eas"]) == {
                0x40B6C0,
            }, selected_capture
            assert selected_capture["row20_source_present"] is True
            assert selected_capture["row20_indirect"] is False
            assert set(selected_capture["row20_target_eas"]) == {
                0x40A81A,
                0x40AA60,
            }, selected_capture
            assert selected_capture["row21_source_present"] is True
            assert selected_capture["row21_indirect"] is False
            assert set(selected_capture["row21_target_eas"]) == {
                0x40A834,
                0x40AC3D,
            }, selected_capture
            assert selected_capture["row22_source_present"] is True
            assert selected_capture["row22_indirect"] is False
            assert set(selected_capture["row22_target_eas"]) == {
                0x40A84E,
                0x40AFDF,
            }, selected_capture
            assert selected_capture["row23_source_present"] is True
            assert selected_capture["row23_indirect"] is False
            assert set(selected_capture["row23_target_eas"]) == {
                0x40A5F0,
                0x40A868,
            }, selected_capture
            assert selected_capture["row25_source_present"] is (
                capture_name == "preopt"
            )
            assert selected_capture["row25_indirect"] is False
            assert set(selected_capture["row25_target_eas"]) == (
                {0x40A64B} if capture_name == "preopt" else set()
            ), selected_capture
            assert selected_capture["row26_source_present"] is True
            assert selected_capture["row26_indirect"] is False
            assert set(selected_capture["row26_target_eas"]) == {
                0x40A8CF,
                0x40ACBF,
            }, selected_capture
            assert selected_capture["row27_source_present"] is True
            assert selected_capture["row27_indirect"] is False
            assert set(selected_capture["row27_target_eas"]) == {
                0x40A8E9,
                0x40B024,
            }, selected_capture
            assert selected_capture["row28_source_present"] is True
            assert selected_capture["row28_indirect"] is False
            assert set(selected_capture["row28_target_eas"]) == {
                0x40A5F0,
                0x40A903,
            }, selected_capture
            assert selected_capture["row29_source_present"] is True
            assert selected_capture["row29_indirect"] is False
            assert set(selected_capture["row29_target_eas"]) == {
                0x40B6C0,
            }, selected_capture
            assert selected_capture["row30_source_present"] is True
            assert selected_capture["row30_indirect"] is False
            assert set(selected_capture["row30_target_eas"]) == {
                0x40A97A,
                0x40AD1E,
            }, selected_capture
            assert selected_capture["row31_source_present"] is True
            assert selected_capture["row31_indirect"] is False
            assert set(selected_capture["row31_target_eas"]) == {
                0x40A994,
                0x40B071,
            }, selected_capture
            assert selected_capture["row32_source_present"] is True
            assert selected_capture["row32_indirect"] is False
            assert set(selected_capture["row32_target_eas"]) == {
                0x40A5F0,
                0x40A9AE,
            }, selected_capture
            assert selected_capture["row33_source_present"] is True
            assert selected_capture["row33_indirect"] is False
            assert set(selected_capture["row33_target_eas"]) == (
                {0x40A607, 0x40B6C0} if capture_name == "preopt" else {0x40B6C0}
            ), selected_capture
            assert selected_capture["row34_source_present"] is True
            assert selected_capture["row34_indirect"] is False
            assert set(selected_capture["row34_target_eas"]) == {
                0x40A9F8,
                0x40AD6E,
            }, selected_capture
            assert selected_capture["row35_source_present"] is True
            assert selected_capture["row35_indirect"] is False
            assert set(selected_capture["row35_target_eas"]) == {
                0x40AA12,
                0x40B0BC,
            }, selected_capture
            assert selected_capture["row36_source_present"] is True
            assert selected_capture["row36_indirect"] is False
            assert set(selected_capture["row36_target_eas"]) == {
                0x40A5F0,
                0x40AA2C,
            }, selected_capture
            assert selected_capture["row37_source_present"] is True
            assert selected_capture["row37_indirect"] is False
            assert set(selected_capture["row37_target_eas"]) == (
                {0x40A607, 0x40B6C0} if capture_name == "preopt" else {0x40A607}
            ), selected_capture
            assert selected_capture["row38_source_present"] is True
            assert selected_capture["row38_indirect"] is False
            assert set(selected_capture["row38_target_eas"]) == {
                0x40AA7A,
                0x40ADBE,
            }, selected_capture
            assert selected_capture["row39_source_present"] is True
            assert selected_capture["row39_indirect"] is False
            assert set(selected_capture["row39_target_eas"]) == {
                0x40AA94,
                0x40B0F2,
            }, selected_capture
            assert selected_capture["row40_source_present"] is True
            assert selected_capture["row40_indirect"] is False
            assert set(selected_capture["row40_target_eas"]) == {
                0x40A5F0,
                0x40AAAE,
            }, selected_capture
            assert selected_capture["row42_source_present"] is (
                capture_name == "preopt"
            ), (capture_name, selected_capture["row42_source_present"])
            assert selected_capture["row42_indirect"] is False
            assert set(selected_capture["row42_target_eas"]) == {
                *({0x40AAFD, 0x40AE1A} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row42_target_eas"])
            assert selected_capture["row43_source_present"] is True
            assert selected_capture["row43_indirect"] is False
            assert set(selected_capture["row43_target_eas"]) == {
                0x40AB17,
                0x40B149,
            }, selected_capture
            assert selected_capture["row44_source_present"] is True
            assert selected_capture["row44_indirect"] is False
            assert set(selected_capture["row44_target_eas"]) == {
                0x40A5F0,
                0x40AB31,
            }, selected_capture
            assert selected_capture["row45_source_present"] is True
            assert selected_capture["row45_indirect"] is False
            assert set(selected_capture["row45_target_eas"]) == {
                0x40B6C0,
                *({0x40AB6A} if capture_name == "preopt" else set()),
            }, (
                capture_name,
                selected_capture["row45_target_eas"],
            )
            assert selected_capture["row46_source_present"] is True
            assert selected_capture["row46_indirect"] is False
            assert set(selected_capture["row46_target_eas"]) == {
                0x40AB90,
                0x40B17F,
            }, selected_capture
            assert selected_capture["row47_source_present"] is True
            assert selected_capture["row47_indirect"] is False
            assert set(selected_capture["row47_target_eas"]) == {
                0x40A5F0,
                0x40ABAA,
            }, selected_capture
            assert selected_capture["row49_source_present"] is True
            assert selected_capture["row49_indirect"] is False
            assert set(selected_capture["row49_target_eas"]) == {
                0x40ABE0,
                0x40B1D0,
            }, selected_capture
            assert selected_capture["row50_source_present"] is True
            assert selected_capture["row50_indirect"] is False
            assert set(selected_capture["row50_target_eas"]) == {
                0x40A5F0,
                0x40ABFA,
            }, selected_capture
            assert selected_capture["row51_source_present"] is True
            assert selected_capture["row51_indirect"] is False
            assert set(selected_capture["row51_target_eas"]) == {
                0x40B6C0,
                *({0x40AC31} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row51_target_eas"])
            assert selected_capture["row52_source_present"] is True
            assert selected_capture["row52_indirect"] is False
            assert set(selected_capture["row52_target_eas"]) == {
                0x40AC56,
                0x40B21C,
            }, selected_capture
            assert selected_capture["row53_source_present"] is True
            assert selected_capture["row53_indirect"] is False
            assert set(selected_capture["row53_target_eas"]) == {
                0x40A5F0,
                0x40AC70,
            }, selected_capture
            assert selected_capture["row54_source_present"] is True
            assert selected_capture["row54_indirect"] is False
            assert set(selected_capture["row54_target_eas"]) == {
                0x40B6C0,
                *({0x40ACB3} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row54_target_eas"])
            assert selected_capture["row55_source_present"] is True
            assert selected_capture["row55_indirect"] is False
            assert set(selected_capture["row55_target_eas"]) == {
                0x40ACD9,
                0x40B26D,
            }, selected_capture
            assert selected_capture["row56_source_present"] is True
            assert selected_capture["row56_indirect"] is False
            assert set(selected_capture["row56_target_eas"]) == {
                0x40A5F0,
                0x40ACF3,
            }, selected_capture
            assert selected_capture["row57_source_present"] is True
            assert selected_capture["row57_indirect"] is False
            assert set(selected_capture["row57_target_eas"]) == {
                0x40B6C0,
                *({0x40AD18} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row57_target_eas"])
            assert selected_capture["row58_source_present"] is True
            assert selected_capture["row58_indirect"] is False
            assert set(selected_capture["row58_target_eas"]) == {
                0x40AD38,
                0x40B2DB,
            }, selected_capture
            assert selected_capture["row59_source_present"] is True
            assert selected_capture["row59_indirect"] is False
            assert set(selected_capture["row59_target_eas"]) == {
                0x40A5F0,
                0x40AD52,
            }, selected_capture
            assert selected_capture["row60_source_present"] is True
            assert selected_capture["row60_indirect"] is False
            assert set(selected_capture["row60_target_eas"]) == {
                0x40B6C0,
                *({0x40A607} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row60_target_eas"])
            assert selected_capture["row61_source_present"] is True
            assert selected_capture["row61_indirect"] is False
            assert set(selected_capture["row61_target_eas"]) == {
                0x40AD88,
                0x40B32C,
            }, (capture_name, selected_capture["row61_target_eas"])
            assert selected_capture["row62_source_present"] is True
            assert selected_capture["row62_indirect"] is False
            assert set(selected_capture["row62_target_eas"]) == {
                0x40A5F0,
                0x40ADA2,
            }, (capture_name, selected_capture["row62_target_eas"])
            assert selected_capture["row63_source_present"] is True
            assert selected_capture["row63_indirect"] is False
            assert set(selected_capture["row63_target_eas"]) == {
                0x40A607,
                *({0x40B6C0} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row63_target_eas"])
            assert selected_capture["row64_source_present"] is True
            assert selected_capture["row64_indirect"] is False
            assert set(selected_capture["row64_target_eas"]) == {
                0x40ADD8,
                0x40B37C,
            }, (capture_name, selected_capture["row64_target_eas"])
            assert selected_capture["row65_source_present"] is True
            assert selected_capture["row65_indirect"] is False
            assert set(selected_capture["row65_target_eas"]) == {
                0x40A5F0,
                0x40ADF2,
            }, (capture_name, selected_capture["row65_target_eas"])
            assert selected_capture["row66_source_present"] is True
            assert selected_capture["row66_indirect"] is False
            assert set(selected_capture["row66_target_eas"]) == {
                0x40A607,
                *({0x40B6C0} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row66_target_eas"])
            assert selected_capture["row67_indirect"] is False
            if capture_name == "preopt":
                assert selected_capture["row67_source_present"] is True
                # PREOPT may coalesce the accepted row-67 carrier with the new
                # row-68 source.  Its own exact route remains 0x40A5CA in the
                # persisted operation observation; the additional successor
                # is row 68's proved true arm, not a row-67 delivery change.
                assert set(selected_capture["row67_target_eas"]) == {
                    0x40A5CA,
                    0x40AE3E,
                }, (
                    capture_name,
                    selected_capture["row67_target_eas"],
                )
            else:
                assert selected_capture["row67_source_present"] is False
                assert selected_capture["row67_target_eas"] == ()
            assert selected_capture["row68_source_present"] is True
            assert selected_capture["row68_indirect"] is False
            assert set(selected_capture["row68_target_eas"]) == {
                0x40A5F0,
                0x40AE3E,
            }, (capture_name, selected_capture["row68_target_eas"])
            assert selected_capture["row69_source_present"] is True
            assert selected_capture["row69_indirect"] is False
            assert set(selected_capture["row69_target_eas"]) == {
                0x40B6C0,
                *({0x40A607} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row69_target_eas"])
            assert selected_capture["row70_source_present"] is True
            assert selected_capture["row70_indirect"] is False
            assert set(selected_capture["row70_target_eas"]) == {
                0x40A5F0,
                0x40AEA5,
            }, (capture_name, selected_capture["row70_target_eas"])
            assert selected_capture["row71_source_present"] is True
            assert selected_capture["row71_indirect"] is False
            assert set(selected_capture["row71_target_eas"]) == {
                0x40B6C0,
                *({0x40AEDA} if capture_name == "preopt" else set()),
            }, (
                capture_name,
                selected_capture["row71_target_eas"],
            )
            assert selected_capture["row72_source_present"] is True
            assert selected_capture["row72_indirect"] is False
            assert set(selected_capture["row72_target_eas"]) == {
                0x40A5F0,
                0x40AF00,
            }, (capture_name, selected_capture["row72_target_eas"])
            assert selected_capture["row73_source_present"] is True
            assert selected_capture["row73_indirect"] is False
            assert set(selected_capture["row73_target_eas"]) == {
                0x40B6C0,
                *({0x40AFD3} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row73_target_eas"])
            assert selected_capture["row74_source_present"] is True
            assert selected_capture["row74_indirect"] is False
            assert set(selected_capture["row74_target_eas"]) == {
                0x40A5F0,
                0x40AFF9,
            }, (capture_name, selected_capture["row74_target_eas"])
            assert selected_capture["row75_source_present"] is True
            assert selected_capture["row75_indirect"] is False
            assert set(selected_capture["row75_target_eas"]) == {
                0x40B6C0,
                *({0x40B01E} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row75_target_eas"])
            assert selected_capture["row76_source_present"] is True
            assert selected_capture["row76_indirect"] is False
            assert set(selected_capture["row76_target_eas"]) == {
                0x40A5F0,
                0x40B03E,
            }, (capture_name, selected_capture["row76_target_eas"])
            assert selected_capture["row77_source_present"] is True
            assert selected_capture["row77_indirect"] is False
            assert set(selected_capture["row77_target_eas"]) == {
                0x40B6C0,
                *({0x40B06B} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row77_target_eas"])
            assert selected_capture["row78_source_present"] is True
            assert selected_capture["row78_indirect"] is False
            assert set(selected_capture["row78_target_eas"]) == {
                0x40A5F0,
                0x40B08B,
            }, (capture_name, selected_capture["row78_target_eas"])
            assert selected_capture["row79_source_present"] is True
            assert selected_capture["row79_indirect"] is False
            assert set(selected_capture["row79_target_eas"]) == {
                0x40A607,
                *({0x40B6C0} if capture_name == "preopt" else set()),
            }, (capture_name, selected_capture["row79_target_eas"])
        assert {0x40A6B4, 0x40A800}.issubset(captures["first_cfg"]["reachable_eas"]), (
            captures["first_cfg"]
        )
        assert captures["calls_count"] == 1
        assert captures["calls"]["indirect"] is False, captures["calls"]
        assert captures["calls"]["row5_indirect"] is False, captures["calls"]
        assert captures["calls"]["row5_source_present"] is False, captures["calls"]
        assert captures["calls"]["row5_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row6_indirect"] is False, captures["calls"]
        assert captures["calls"]["row6_source_present"] is False, captures["calls"]
        assert captures["calls"]["row6_target_eas"] == (), captures["calls"]
        assert captures["calls"]["selected_indirect"] is False, captures["calls"]
        assert captures["calls"]["selected_source_present"] is False, captures["calls"]
        assert captures["calls"]["row11_indirect"] is False, captures["calls"]
        assert captures["calls"]["row11_source_present"] is False, captures["calls"]
        assert captures["calls"]["row12_indirect"] is False, captures["calls"]
        assert captures["calls"]["row12_source_present"] is False, captures["calls"]
        assert captures["calls"]["row20_indirect"] is False, captures["calls"]
        assert captures["calls"]["row20_source_present"] is False, captures["calls"]
        assert captures["calls"]["row21_indirect"] is False, captures["calls"]
        assert captures["calls"]["row21_source_present"] is False, captures["calls"]
        assert captures["calls"]["row22_indirect"] is False, captures["calls"]
        assert captures["calls"]["row22_source_present"] is False, captures["calls"]
        assert captures["calls"]["row23_indirect"] is False, captures["calls"]
        assert captures["calls"]["row23_source_present"] is False, captures["calls"]
        assert captures["calls"]["row25_source_present"] is False, captures["calls"]
        assert captures["calls"]["row25_indirect"] is False, captures["calls"]
        assert captures["calls"]["row25_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row26_indirect"] is False, captures["calls"]
        assert captures["calls"]["row26_source_present"] is False, captures["calls"]
        assert captures["calls"]["row27_indirect"] is False, captures["calls"]
        assert captures["calls"]["row27_source_present"] is False, captures["calls"]
        assert captures["calls"]["row28_indirect"] is False, captures["calls"]
        assert captures["calls"]["row28_source_present"] is False, captures["calls"]
        assert captures["calls"]["row29_indirect"] is False, captures["calls"]
        assert captures["calls"]["row29_source_present"] is False, captures["calls"]
        assert captures["calls"]["row29_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row30_indirect"] is False, captures["calls"]
        assert captures["calls"]["row30_source_present"] is False, captures["calls"]
        assert captures["calls"]["row30_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row31_indirect"] is False, captures["calls"]
        assert captures["calls"]["row31_source_present"] is False, captures["calls"]
        assert captures["calls"]["row31_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row32_indirect"] is False, captures["calls"]
        assert captures["calls"]["row32_source_present"] is False, captures["calls"]
        assert captures["calls"]["row32_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row33_indirect"] is False, captures["calls"]
        assert captures["calls"]["row33_source_present"] is False, captures["calls"]
        assert captures["calls"]["row33_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row34_indirect"] is False, captures["calls"]
        assert captures["calls"]["row34_source_present"] is False, captures["calls"]
        assert captures["calls"]["row34_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row35_indirect"] is False, captures["calls"]
        assert captures["calls"]["row35_source_present"] is False, captures["calls"]
        assert captures["calls"]["row35_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row36_indirect"] is False, captures["calls"]
        assert captures["calls"]["row36_source_present"] is False, captures["calls"]
        assert captures["calls"]["row36_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row37_indirect"] is False, captures["calls"]
        assert captures["calls"]["row37_source_present"] is False, captures["calls"]
        assert captures["calls"]["row37_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row38_indirect"] is False, captures["calls"]
        assert captures["calls"]["row38_source_present"] is False, captures["calls"]
        assert captures["calls"]["row38_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row39_indirect"] is False, captures["calls"]
        assert captures["calls"]["row39_source_present"] is False, captures["calls"]
        assert captures["calls"]["row39_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row40_indirect"] is False, captures["calls"]
        assert captures["calls"]["row40_source_present"] is False, captures["calls"]
        assert captures["calls"]["row40_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row42_indirect"] is False, captures["calls"]
        assert captures["calls"]["row42_source_present"] is False, captures["calls"]
        assert captures["calls"]["row42_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row43_indirect"] is False, captures["calls"]
        assert captures["calls"]["row43_source_present"] is False, captures["calls"]
        assert captures["calls"]["row43_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row44_indirect"] is False, captures["calls"]
        assert captures["calls"]["row44_source_present"] is False, captures["calls"]
        assert captures["calls"]["row44_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row45_indirect"] is False, captures["calls"]
        assert captures["calls"]["row45_source_present"] is False, captures["calls"]
        assert captures["calls"]["row45_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row46_indirect"] is False, captures["calls"]
        assert captures["calls"]["row46_source_present"] is False, captures["calls"]
        assert captures["calls"]["row46_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row47_indirect"] is False, captures["calls"]
        assert captures["calls"]["row47_source_present"] is False, captures["calls"]
        assert captures["calls"]["row47_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row49_indirect"] is False, captures["calls"]
        assert captures["calls"]["row49_source_present"] is False, captures["calls"]
        assert captures["calls"]["row49_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row50_indirect"] is False, captures["calls"]
        assert captures["calls"]["row50_source_present"] is False, captures["calls"]
        assert captures["calls"]["row50_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row51_indirect"] is False, captures["calls"]
        assert captures["calls"]["row51_source_present"] is False, captures["calls"]
        assert captures["calls"]["row51_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row52_indirect"] is False, captures["calls"]
        assert captures["calls"]["row52_source_present"] is False, captures["calls"]
        assert captures["calls"]["row52_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row53_indirect"] is False, captures["calls"]
        assert captures["calls"]["row53_source_present"] is False, captures["calls"]
        assert captures["calls"]["row53_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row54_indirect"] is False, captures["calls"]
        assert captures["calls"]["row54_source_present"] is False, captures["calls"]
        assert captures["calls"]["row54_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row55_indirect"] is False, captures["calls"]
        assert captures["calls"]["row55_source_present"] is False, captures["calls"]
        assert captures["calls"]["row55_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row56_indirect"] is False, captures["calls"]
        assert captures["calls"]["row56_source_present"] is False, captures["calls"]
        assert captures["calls"]["row56_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row57_indirect"] is False, captures["calls"]
        assert captures["calls"]["row57_source_present"] is False, captures["calls"]
        assert captures["calls"]["row57_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row58_indirect"] is False, captures["calls"]
        assert captures["calls"]["row58_source_present"] is False, captures["calls"]
        assert captures["calls"]["row58_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row59_indirect"] is False, captures["calls"]
        assert captures["calls"]["row59_source_present"] is False, captures["calls"]
        assert captures["calls"]["row59_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row60_indirect"] is False, captures["calls"]
        assert captures["calls"]["row60_source_present"] is False, captures["calls"]
        assert captures["calls"]["row60_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row61_indirect"] is False, captures["calls"]
        assert captures["calls"]["row61_source_present"] is False, captures["calls"]
        assert captures["calls"]["row61_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row62_indirect"] is False, captures["calls"]
        assert captures["calls"]["row62_source_present"] is False, captures["calls"]
        assert captures["calls"]["row62_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row63_indirect"] is False, captures["calls"]
        assert captures["calls"]["row63_source_present"] is False, captures["calls"]
        assert captures["calls"]["row63_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row64_indirect"] is False, captures["calls"]
        assert captures["calls"]["row64_source_present"] is False, captures["calls"]
        assert captures["calls"]["row64_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row65_indirect"] is False, captures["calls"]
        assert captures["calls"]["row65_source_present"] is False, captures["calls"]
        assert captures["calls"]["row65_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row66_indirect"] is False, captures["calls"]
        assert captures["calls"]["row66_source_present"] is False, captures["calls"]
        assert captures["calls"]["row66_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row67_indirect"] is False, captures["calls"]
        assert captures["calls"]["row67_source_present"] is False, captures["calls"]
        assert captures["calls"]["row67_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row68_indirect"] is False, captures["calls"]
        assert captures["calls"]["row68_source_present"] is False, captures["calls"]
        assert captures["calls"]["row68_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row69_indirect"] is False, captures["calls"]
        assert captures["calls"]["row69_source_present"] is False, captures["calls"]
        assert captures["calls"]["row69_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row70_indirect"] is False, captures["calls"]
        assert captures["calls"]["row70_source_present"] is False, captures["calls"]
        assert captures["calls"]["row70_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row71_indirect"] is False, captures["calls"]
        assert captures["calls"]["row71_source_present"] is False, captures["calls"]
        assert captures["calls"]["row71_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row72_indirect"] is False, captures["calls"]
        assert captures["calls"]["row72_source_present"] is False, captures["calls"]
        assert captures["calls"]["row72_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row73_indirect"] is False, captures["calls"]
        assert captures["calls"]["row73_source_present"] is False, captures["calls"]
        assert captures["calls"]["row73_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row74_indirect"] is False, captures["calls"]
        assert captures["calls"]["row74_source_present"] is False, captures["calls"]
        assert captures["calls"]["row74_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row75_indirect"] is False, captures["calls"]
        assert captures["calls"]["row75_source_present"] is False, captures["calls"]
        assert captures["calls"]["row75_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row76_indirect"] is False, captures["calls"]
        assert captures["calls"]["row76_source_present"] is False, captures["calls"]
        assert captures["calls"]["row76_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row77_indirect"] is False, captures["calls"]
        assert captures["calls"]["row77_source_present"] is False, captures["calls"]
        assert captures["calls"]["row77_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row78_indirect"] is False, captures["calls"]
        assert captures["calls"]["row78_source_present"] is False, captures["calls"]
        assert captures["calls"]["row78_target_eas"] == (), captures["calls"]
        assert captures["calls"]["row79_indirect"] is False, captures["calls"]
        assert captures["calls"]["row79_source_present"] is False, captures["calls"]
        assert captures["calls"]["row79_target_eas"] == (), captures["calls"]
        assert captures["calls"]["setcc_indirect"] is False, captures["calls"]
        assert captures["calls"]["setcc_source_present"] is True, captures["calls"]
        assert captures["calls"]["scaled_setcc_indirect"] is False, captures["calls"]
        if captures["calls"]["scaled_setcc_source_present"]:
            assert set(captures["calls"]["scaled_setcc_target_eas"]) == {
                0x40A794,
                0x40AEE6,
            }, captures["calls"]
        assert captures["calls"]["row18_indirect"] is False, captures["calls"]
        assert captures["calls"]["row19_source_present"] is False, captures["calls"]
        assert captures["calls"]["row19_indirect"] is False, captures["calls"]
        assert captures["calls"]["row19_target_eas"] == (), captures["calls"]
        if captures["calls"]["source_present"]:
            assert set(captures["calls"]["target_eas"]) == {
                0x40A607,
                0x40B6C0,
            }, captures["calls"]
        assert 0x40B6C0 in captures["calls"]["reachable_eas"], captures["calls"]
        headless.stop()
        print("checksum-worker:stopped", flush=True)
    finally:
        if hook is not None:
            hook.unhook()
        try:
            import d810.headless as headless

            headless.stop()
        except Exception:
            pass
        from d810.core.observability import close_observability_session

        close_observability_session()
        diag_output = os.environ.get("D810_RHAD_GENERATED_CHECKSUM_DIAG_OUTPUT")
        if diag_output:
            from d810.core.diag import find_latest_diag_db_path

            diag_path = find_latest_diag_db_path(_FUNCTION_EA)
            if diag_path is not None:
                destination = pathlib.Path(diag_output).resolve()
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(diag_path, destination)
        idapro.close_database(False)


def test_a560_generated_checksum_commits_and_reaches_ctree(
    tmp_path: pathlib.Path,
) -> None:
    fixture = _fixture()
    if not fixture.is_file():
        pytest.skip("real Rhad loader fixture unavailable")
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == _EXPECTED_SHA256
    binary = tmp_path / fixture.name
    diag_path = tmp_path / "a560-generated-checksum.diag.sqlite3"
    shutil.copy2(fixture, binary)
    for suffix in _SIDECARS:
        binary.with_suffix(suffix).unlink(missing_ok=True)
        pathlib.Path(str(binary) + suffix).unlink(missing_ok=True)
    before = hashlib.sha256(binary.read_bytes()).hexdigest()
    env = dict(os.environ)
    env.pop("PYTEST_CURRENT_TEST", None)
    env["PYTHONPATH"] = os.pathsep.join(
        (str(_REPO / "src"), str(_REPO / "tests"), env.get("PYTHONPATH", ""))
    )
    env["D810_DIAG_SNAPSHOT"] = "1"
    env["D810_RHAD_GENERATED_CHECKSUM_DIAG_OUTPUT"] = str(diag_path)
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(pathlib.Path(__file__).resolve()),
                "--worker",
                str(binary),
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=55,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        pytest.fail(
            "checksum worker timed out\n"
            f"stdout excerpt:\n{_output_excerpt(error.stdout)}\n"
            f"stderr excerpt:\n{_output_excerpt(error.stderr)}"
        )
    assert result.returncode == 0, (
        f"checksum worker failed ({result.returncode})\n"
        f"stdout excerpt:\n{_output_excerpt(result.stdout)}\n"
        f"stderr excerpt:\n{_output_excerpt(result.stderr)}"
    )
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == before
    assert diag_path.is_file()
    with sqlite3.connect(diag_path) as connection:
        lifecycle_rows = connection.execute(
            "SELECT event_kind, maturity, phase, payload_json "
            "FROM lifecycle_events "
            "WHERE event_kind LIKE 'rhad_generated_checksum%' "
            "ORDER BY event_id"
        ).fetchall()
        assert tuple(row[0] for row in lifecycle_rows[:3]) == (
            "rhad_generated_checksum_preparation",
            "rhad_generated_checksum_compiled",
            "rhad_generated_checksum_published",
        )
        maturity_rows = tuple(
            row
            for row in lifecycle_rows
            if row[0] == "rhad_generated_checksum_maturity"
        )
        assert tuple(row[1] for row in maturity_rows) == (
            "MMAT_GENERATED",
            "MMAT_PREOPTIMIZED",
            "MMAT_LOCOPT",
            "MMAT_CALLS",
        )
        assert all(bool(json.loads(row[3])["passed"]) for row in maturity_rows)
        compiled_payload = json.loads(lifecycle_rows[1][3])
        row16_artifact_identity = (
            "sha256:cab149ee6cce29957798829cceba0a2da5e17bbf3fda4c6d55dad62d64ec3785"
        )
        row17_artifact_identity = (
            "sha256:a67a3d2cc432df11ca627c90f06f3a854004a9463a529ee1d0cdf1f759406e67"
        )
        row68_artifact_identity = (
            "sha256:9eb674af190cee8d9b391605feb930a59bcf708c9fbb519f2d8bd26cac27fdd0"
        )
        assert compiled_payload["plan_id"].endswith(
            compiled_payload["aggregate_program_identity"]
        )
        proof_artifacts = {
            artifact["proof"]["binding"]["operation_id"]: artifact
            for artifact in compiled_payload["proof_artifacts"]
        }
        assert tuple(proof_artifacts) == (
            "rhad:route@0x40A77C",
            "rhad:route@0x40A792",
            "rhad:route@0x40AE3C",
        )
        for operation_id, reference_order, schema_version, content_identity in (
            ("rhad:route@0x40A77C", 16, 1, row16_artifact_identity),
            ("rhad:route@0x40A792", 17, 2, row17_artifact_identity),
            ("rhad:route@0x40AE3C", 68, 1, row68_artifact_identity),
        ):
            artifact = proof_artifacts[operation_id]
            assert artifact["content_identity"] == content_identity
            assert artifact["proof"]["artifact_type"] == (
                "rhad_setcc_indexed_table_proof"
            )
            assert artifact["proof"]["schema_version"] == schema_version
            assert artifact["proof"]["binding"] == {
                "function_ea": 0x40A560,
                "input_sha256": _EXPECTED_SHA256,
                "operation_id": operation_id,
                "reference_commit": "21b0d4783703bc4fb6910cfae51d92cd683d2c65",
                "reference_order": reference_order,
            }
        assert tuple(compiled_payload["operation_ids"]) == _REFERENCE_OPERATION_IDS
        assert tuple(compiled_payload["imported_block_ids"]) == _IMPORTED_BLOCK_IDS
        assert compiled_payload["imported_block_count"] == len(_IMPORTED_BLOCK_IDS)
        reference_payloads = {
            row["operation_id"]: json.loads(row["reference_ledger_json"])
            for row in compiled_payload["reference_operations"]
        }
        assert set(reference_payloads) == set(_REFERENCE_OPERATION_IDS)
        direct_reference = reference_payloads["route:rhad-direct@0x40A619"]
        assert direct_reference["operation_category"] == "direct_route"
        assert direct_reference["reference_operation_id"] == "rhad:route@0x40A619"
        assert direct_reference["reference_order"] == 2
        assert direct_reference["operation_variant"] == "simple_indirect_jump"
        assert direct_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert direct_reference["source_native_ea"] == 0x40A607
        assert direct_reference["source_block_anchor_ea"] == 0x40A615
        assert direct_reference["transfer_ea"] == 0x40A619
        assert direct_reference["direct_target_block_id"] == "native@0x40A61B"
        row3_reference = reference_payloads["route:rhad-direct@0x40A631"]
        assert row3_reference["reference_operation_id"] == "rhad:route@0x40A631"
        assert row3_reference["reference_order"] == 3
        assert row3_reference["operation_variant"] == "simple_indirect_jump"
        assert row3_reference["source_native_ea"] == 0x40A61B
        assert row3_reference["source_block_anchor_ea"] == 0x40A62D
        assert row3_reference["transfer_ea"] == 0x40A631
        assert row3_reference["direct_target_block_id"] == "native@0x40A633"
        assert row3_reference["boundary_exit_eas"] == [0x40A64B, 0x40A8B5]
        row4_reference = reference_payloads["route:rhad-direct@0x40A649"]
        assert row4_reference["reference_operation_id"] == "rhad:route@0x40A649"
        assert row4_reference["reference_order"] == 4
        assert row4_reference["operation_variant"] == "simple_indirect_jump"
        assert row4_reference["source_native_ea"] == 0x40A633
        assert row4_reference["source_block_anchor_ea"] == 0x40A645
        assert row4_reference["transfer_ea"] == 0x40A649
        assert row4_reference["direct_target_block_id"] == "native@0x40A8B5"
        assert row4_reference["boundary_exit_eas"] == [0x40ACBF]
        row5_reference = reference_payloads["route:rhad-direct@0x40A661"]
        assert row5_reference["reference_operation_id"] == "rhad:route@0x40A661"
        assert row5_reference["reference_order"] == 5
        assert row5_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row5_reference["operation_variant"] == "simple_indirect_jump"
        assert row5_reference["source_native_ea"] == 0x40A64B
        assert row5_reference["source_block_anchor_ea"] == 0x40A65D
        assert row5_reference["transfer_ea"] == 0x40A661
        assert row5_reference["direct_target_block_id"] == "native@0x40A663"
        assert row5_reference["owned_corridor_instruction_eas"] == [
            0x40A64B,
            0x40A65D,
            0x40A65F,
            0x40A661,
        ]
        assert row5_reference["imported_closure_block_ids"] == [
            "native@0x40A64B",
            "native@0x40A65D",
            "native@0x40A661",
            "native@0x40AAF1",
            "native@0x40AAFB",
            "native@0x40A663",
            "native@0x40A675",
            "native@0x40A679",
            "native@0x40AE1A",
            "native@0x40AE24",
        ]
        assert row5_reference["boundary_exit_eas"] == [
            0x40A5CA,
            0x40AAFD,
            0x40AE26,
        ]
        row6_reference = reference_payloads["route:rhad-direct@0x40A679"]
        assert row6_reference["reference_operation_id"] == "rhad:route@0x40A679"
        assert row6_reference["reference_order"] == 6
        assert row6_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row6_reference["operation_variant"] == "simple_indirect_jump"
        assert row6_reference["source_native_ea"] == 0x40A663
        assert row6_reference["source_block_anchor_ea"] == 0x40A675
        assert row6_reference["transfer_ea"] == 0x40A679
        assert row6_reference["direct_target_block_id"] == "native@0x40AE26"
        assert row6_reference["owned_corridor_instruction_eas"] == [
            0x40A663,
            0x40A675,
            0x40A677,
            0x40A679,
        ]
        assert row6_reference["imported_closure_block_ids"] == [
            "native@0x40AE26",
            "native@0x40AE3C",
        ]
        assert row6_reference["boundary_exit_eas"] == [0x40A5F0, 0x40AE3E]
        selected_reference = reference_payloads["rhad:route@0x40A6A4"]
        assert selected_reference["reference_order"] == 8
        assert selected_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert selected_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert selected_reference["source_native_ea"] == 0x40A68C
        assert selected_reference["condition_producer_ea"] == 0x40A692
        assert selected_reference["transfer_ea"] == 0x40A6A4
        assert selected_reference["true_target_ea"] == 0x40A6A6
        assert selected_reference["false_target_ea"] == 0x40A800
        assert selected_reference["true_target_block_id"] == "native@0x40A6A6"
        assert selected_reference["false_target_block_id"] == "native@0x40A800"
        row9_reference = reference_payloads["rhad:route@0x40A6BE"]
        assert row9_reference["reference_order"] == 9
        assert row9_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row9_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row9_reference["source_native_ea"] == 0x40A6A6
        assert row9_reference["condition_producer_ea"] == 0x40A6AC
        assert row9_reference["predicate_anchor_ea"] == 0x40A6B2
        assert row9_reference["predicate_kind"] == "slt"
        assert row9_reference["observed_predicate_kind"] == "sge"
        assert row9_reference["transfer_ea"] == 0x40A6BE
        assert row9_reference["true_target_ea"] == 0x40A6C0
        assert row9_reference["false_target_ea"] == 0x40A960
        assert row9_reference["true_target_block_id"] == "native@0x40A6C0"
        assert row9_reference["false_target_block_id"] == "native@0x40A960"
        assert row9_reference["boundary_exit_eas"] == [
            0x40A6DA,
            0x40AB76,
            0x40AD1E,
        ]
        row10_reference = reference_payloads["rhad:route@0x40A6D8"]
        assert row10_reference["reference_order"] == 10
        assert row10_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row10_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row10_reference["source_native_ea"] == 0x40A6C0
        assert row10_reference["condition_producer_ea"] == 0x40A6C6
        assert row10_reference["predicate_anchor_ea"] == 0x40A6CC
        assert row10_reference["predicate_kind"] == "slt"
        assert row10_reference["observed_predicate_kind"] == "sge"
        assert row10_reference["transfer_ea"] == 0x40A6D8
        assert row10_reference["true_target_ea"] == 0x40A6DA
        assert row10_reference["false_target_ea"] == 0x40AB76
        assert row10_reference["true_target_block_id"] == "native@0x40A6DA"
        assert row10_reference["false_target_block_id"] == "native@0x40AB76"
        assert row10_reference["boundary_exit_eas"] == [
            0x40A6F4,
            0x40AE8B,
            0x40B17F,
        ]
        row11_reference = reference_payloads["rhad:route@0x40A6F2"]
        assert row11_reference["reference_order"] == 11
        assert row11_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row11_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row11_reference["source_native_ea"] == 0x40A6DA
        assert row11_reference["condition_producer_ea"] == 0x40A6E0
        assert row11_reference["predicate_anchor_ea"] == 0x40A6E6
        assert row11_reference["predicate_kind"] == "slt"
        assert row11_reference["observed_predicate_kind"] == "sge"
        assert row11_reference["transfer_ea"] == 0x40A6F2
        assert row11_reference["true_target_ea"] == 0x40A6F4
        assert row11_reference["false_target_ea"] == 0x40AE8B
        assert row11_reference["true_target_block_id"] == "native@0x40A6F4"
        assert row11_reference["false_target_block_id"] == "native@0x40AE8B"
        assert row11_reference["boundary_exit_eas"] == [0x40A5F0, 0x40A70E]
        row12_reference = reference_payloads["rhad:route@0x40A70C"]
        assert row12_reference["reference_order"] == 12
        assert row12_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row12_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row12_reference["source_native_ea"] == 0x40A6F4
        assert row12_reference["condition_producer_ea"] == 0x40A6FA
        assert row12_reference["predicate_anchor_ea"] == 0x40A700
        assert row12_reference["predicate_kind"] == "eq"
        assert row12_reference["observed_predicate_kind"] == "ne"
        assert row12_reference["transfer_ea"] == 0x40A70C
        assert row12_reference["true_target_ea"] == 0x40A70E
        assert row12_reference["false_target_ea"] == 0x40A5F0
        assert row12_reference["true_target_block_id"] == "native@0x40A70E"
        assert row12_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row12_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row20_reference = reference_payloads["rhad:route@0x40A818"]
        assert row20_reference["reference_order"] == 20
        assert row20_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row20_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row20_reference["source_native_ea"] == 0x40A800
        assert row20_reference["condition_producer_ea"] == 0x40A806
        assert row20_reference["predicate_anchor_ea"] == 0x40A80C
        assert row20_reference["predicate_kind"] == "slt"
        assert row20_reference["observed_predicate_kind"] == "sge"
        assert row20_reference["transfer_ea"] == 0x40A818
        assert row20_reference["true_target_ea"] == 0x40A81A
        assert row20_reference["false_target_ea"] == 0x40AA60
        assert row20_reference["true_target_block_id"] == "native@0x40A81A"
        assert row20_reference["false_target_block_id"] == "native@0x40AA60"
        assert row20_reference["boundary_exit_eas"] == [
            0x40A834,
            0x40AC3D,
            0x40ADBE,
        ]
        row21_reference = reference_payloads["rhad:route@0x40A832"]
        assert row21_reference["reference_order"] == 21
        assert row21_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row21_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row21_reference["source_native_ea"] == 0x40A81A
        assert row21_reference["condition_producer_ea"] == 0x40A820
        assert row21_reference["predicate_anchor_ea"] == 0x40A826
        assert row21_reference["predicate_kind"] == "slt"
        assert row21_reference["observed_predicate_kind"] == "sge"
        assert row21_reference["transfer_ea"] == 0x40A832
        assert row21_reference["true_target_ea"] == 0x40A834
        assert row21_reference["false_target_ea"] == 0x40AC3D
        assert row21_reference["true_target_block_id"] == "native@0x40A834"
        assert row21_reference["false_target_block_id"] == "native@0x40AC3D"
        assert row21_reference["boundary_exit_eas"] == [
            0x40A84E,
            0x40AFDF,
            0x40B21C,
        ]
        row22_reference = reference_payloads["rhad:route@0x40A84C"]
        assert row22_reference["reference_order"] == 22
        assert row22_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row22_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row22_reference["source_native_ea"] == 0x40A834
        assert row22_reference["condition_producer_ea"] == 0x40A83A
        assert row22_reference["predicate_anchor_ea"] == 0x40A840
        assert row22_reference["predicate_kind"] == "slt"
        assert row22_reference["observed_predicate_kind"] == "sge"
        assert row22_reference["transfer_ea"] == 0x40A84C
        assert row22_reference["true_target_ea"] == 0x40A84E
        assert row22_reference["false_target_ea"] == 0x40AFDF
        assert row22_reference["true_target_block_id"] == "native@0x40A84E"
        assert row22_reference["false_target_block_id"] == "native@0x40AFDF"
        assert row22_reference["boundary_exit_eas"] == [0x40A5F0, 0x40A868]
        row23_reference = reference_payloads["rhad:route@0x40A866"]
        assert row23_reference["reference_order"] == 23
        assert row23_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row23_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row23_reference["source_native_ea"] == 0x40A84E
        assert row23_reference["condition_producer_ea"] == 0x40A854
        assert row23_reference["predicate_anchor_ea"] == 0x40A85A
        assert row23_reference["predicate_kind"] == "eq"
        assert row23_reference["observed_predicate_kind"] == "ne"
        assert row23_reference["transfer_ea"] == 0x40A866
        assert row23_reference["true_target_ea"] == 0x40A868
        assert row23_reference["false_target_ea"] == 0x40A5F0
        assert row23_reference["true_target_block_id"] == "native@0x40A868"
        assert row23_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row23_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row25_reference = reference_payloads["route:rhad-direct@0x40A8B3"]
        assert row25_reference["reference_operation_id"] == "rhad:route@0x40A8B3"
        assert row25_reference["reference_order"] == 25
        assert row25_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row25_reference["operation_variant"] == "simple_indirect_jump"
        assert row25_reference["source_native_ea"] == 0x40A63F
        assert row25_reference["source_block_anchor_ea"] == 0x40A8A9
        assert row25_reference["transfer_ea"] == 0x40A8B3
        assert row25_reference["direct_target_block_id"] == "native@0x40A64B"
        assert row25_reference["owned_corridor_instruction_eas"] == [
            0x40A63F,
            0x40A8A9,
            0x40A8AF,
            0x40A8B1,
            0x40A8B3,
        ]
        assert row25_reference["imported_closure_block_ids"] == [
            "native@0x40A64B",
            "native@0x40A65D",
            "native@0x40A661",
            "native@0x40AAF1",
            "native@0x40AAFB",
        ]
        assert row25_reference["boundary_exit_eas"] == [0x40A663, 0x40AAFD]
        row26_reference = reference_payloads["rhad:route@0x40A8CD"]
        assert row26_reference["reference_order"] == 26
        assert row26_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row26_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row26_reference["source_native_ea"] == 0x40A8B5
        assert row26_reference["condition_producer_ea"] == 0x40A8BB
        assert row26_reference["predicate_anchor_ea"] == 0x40A8C1
        assert row26_reference["predicate_kind"] == "slt"
        assert row26_reference["observed_predicate_kind"] == "sge"
        assert row26_reference["transfer_ea"] == 0x40A8CD
        assert row26_reference["true_target_ea"] == 0x40A8CF
        assert row26_reference["false_target_ea"] == 0x40ACBF
        assert row26_reference["true_target_block_id"] == "native@0x40A8CF"
        assert row26_reference["false_target_block_id"] == "native@0x40ACBF"
        assert row26_reference["boundary_exit_eas"] == [
            0x40A8E9,
            0x40B024,
            0x40B26D,
        ]
        row27_reference = reference_payloads["rhad:route@0x40A8E7"]
        assert row27_reference["reference_order"] == 27
        assert row27_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row27_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row27_reference["source_native_ea"] == 0x40A8CF
        assert row27_reference["condition_producer_ea"] == 0x40A8D5
        assert row27_reference["predicate_anchor_ea"] == 0x40A8DB
        assert row27_reference["predicate_kind"] == "slt"
        assert row27_reference["observed_predicate_kind"] == "sge"
        assert row27_reference["comparison_constant"] == 0x0CDF90C9
        assert row27_reference["transfer_ea"] == 0x40A8E7
        assert row27_reference["true_target_ea"] == 0x40A8E9
        assert row27_reference["false_target_ea"] == 0x40B024
        assert row27_reference["true_target_block_id"] == "native@0x40A8E9"
        assert row27_reference["false_target_block_id"] == "native@0x40B024"
        assert row27_reference["boundary_exit_eas"] == [0x40A5F0, 0x40A903]
        row28_reference = reference_payloads["rhad:route@0x40A901"]
        assert row28_reference["reference_order"] == 28
        assert row28_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row28_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row28_reference["source_native_ea"] == 0x40A8E9
        assert row28_reference["condition_producer_ea"] == 0x40A8EF
        assert row28_reference["predicate_anchor_ea"] == 0x40A8F5
        assert row28_reference["predicate_kind"] == "eq"
        assert row28_reference["observed_predicate_kind"] == "ne"
        assert row28_reference["comparison_constant"] == 0x0BB2D365
        assert row28_reference["transfer_ea"] == 0x40A901
        assert row28_reference["true_target_ea"] == 0x40A903
        assert row28_reference["false_target_ea"] == 0x40A5F0
        assert row28_reference["true_target_block_id"] == "native@0x40A903"
        assert row28_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row28_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row29_reference = reference_payloads["route:rhad-direct@0x40A95E"]
        assert row29_reference["reference_operation_id"] == "rhad:route@0x40A95E"
        assert row29_reference["reference_order"] == 29
        assert row29_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row29_reference["operation_variant"] == "simple_indirect_jump"
        assert row29_reference["source_native_ea"] == 0x40A93C
        assert row29_reference["source_block_anchor_ea"] == 0x40A954
        assert row29_reference["transfer_ea"] == 0x40A95E
        assert row29_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row29_reference["boundary_exit_eas"] == [0x40B790]
        row30_reference = reference_payloads["rhad:route@0x40A978"]
        assert row30_reference["reference_order"] == 30
        assert row30_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row30_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row30_reference["source_native_ea"] == 0x40A960
        assert row30_reference["condition_producer_ea"] == 0x40A966
        assert row30_reference["predicate_anchor_ea"] == 0x40A96C
        assert row30_reference["predicate_kind"] == "slt"
        assert row30_reference["observed_predicate_kind"] == "sge"
        assert row30_reference["comparison_constant"] == 0x636961E8
        assert row30_reference["transfer_ea"] == 0x40A978
        assert row30_reference["true_target_ea"] == 0x40A97A
        assert row30_reference["false_target_ea"] == 0x40AD1E
        assert row30_reference["true_target_block_id"] == "native@0x40A97A"
        assert row30_reference["false_target_block_id"] == "native@0x40AD1E"
        assert row30_reference["boundary_exit_eas"] == [
            0x40A994,
            0x40B071,
            0x40B55B,
        ]
        row31_reference = reference_payloads["rhad:route@0x40A992"]
        assert row31_reference["reference_order"] == 31
        assert row31_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row31_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row31_reference["source_native_ea"] == 0x40A97A
        assert row31_reference["condition_producer_ea"] == 0x40A980
        assert row31_reference["predicate_anchor_ea"] == 0x40A986
        assert row31_reference["predicate_kind"] == "slt"
        assert row31_reference["observed_predicate_kind"] == "sge"
        assert row31_reference["comparison_constant"] == 0x5E07BA29
        assert row31_reference["transfer_ea"] == 0x40A992
        assert row31_reference["true_target_ea"] == 0x40A994
        assert row31_reference["false_target_ea"] == 0x40B071
        assert row31_reference["true_target_block_id"] == "native@0x40A994"
        assert row31_reference["false_target_block_id"] == "native@0x40B071"
        assert row31_reference["boundary_exit_eas"] == [0x40A5F0, 0x40A9AE]
        row32_reference = reference_payloads["rhad:route@0x40A9AC"]
        assert row32_reference["reference_order"] == 32
        assert row32_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row32_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row32_reference["source_native_ea"] == 0x40A994
        assert row32_reference["condition_producer_ea"] == 0x40A99A
        assert row32_reference["predicate_anchor_ea"] == 0x40A9A0
        assert row32_reference["predicate_kind"] == "eq"
        assert row32_reference["observed_predicate_kind"] == "ne"
        assert row32_reference["comparison_constant"] == 0x4DFFC906
        assert row32_reference["transfer_ea"] == 0x40A9AC
        assert row32_reference["true_target_ea"] == 0x40A9AE
        assert row32_reference["false_target_ea"] == 0x40A5F0
        assert row32_reference["true_target_block_id"] == "native@0x40A9AE"
        assert row32_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row32_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row33_reference = reference_payloads["rhad:route@0x40A9DC"]
        assert row33_reference["reference_order"] == 33
        assert row33_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row33_reference["operation_variant"] == "cmov_selected_indirect"
        assert row33_reference["source_native_ea"] == 0x40A9B3
        assert row33_reference["source_block_anchor_ea"] == 0x40A9AE
        assert row33_reference["condition_producer_ea"] == 0x40A9C7
        assert row33_reference["predicate_anchor_ea"] == 0x40A9D5
        assert row33_reference["predicate_kind"] == "slt"
        assert row33_reference["observed_predicate_kind"] == "sge"
        assert row33_reference["comparison_constant"] == 0x0BB2D365
        assert row33_reference["transfer_ea"] == 0x40A9DC
        assert row33_reference["true_target_ea"] == 0x40B6C0
        assert row33_reference["false_target_ea"] == 0x40A607
        assert row33_reference["true_target_block_id"] == "native@0x40B6C0"
        assert row33_reference["false_target_block_id"] == "native@0x40A607"
        assert row33_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row34_reference = reference_payloads["rhad:route@0x40A9F6"]
        assert row34_reference["reference_order"] == 34
        assert row34_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row34_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row34_reference["source_native_ea"] == 0x40A9DE
        assert row34_reference["source_block_anchor_ea"] == 0x40A9F2
        assert row34_reference["condition_producer_ea"] == 0x40A9E4
        assert row34_reference["predicate_anchor_ea"] == 0x40A9EA
        assert row34_reference["predicate_kind"] == "slt"
        assert row34_reference["observed_predicate_kind"] == "sge"
        assert row34_reference["comparison_constant"] == 0x2B8162DC
        assert row34_reference["transfer_ea"] == 0x40A9F6
        assert row34_reference["true_target_ea"] == 0x40A9F8
        assert row34_reference["false_target_ea"] == 0x40AD6E
        assert row34_reference["true_target_block_id"] == "native@0x40A9F8"
        assert row34_reference["false_target_block_id"] == "native@0x40AD6E"
        assert row34_reference["boundary_exit_eas"] == [
            0x40AA12,
            0x40AD88,
            0x40B0BC,
            0x40B32C,
        ]
        row35_reference = reference_payloads["rhad:route@0x40AA10"]
        assert row35_reference["reference_order"] == 35
        assert row35_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row35_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row35_reference["source_native_ea"] == 0x40A9F8
        assert row35_reference["source_block_anchor_ea"] == 0x40AA0C
        assert row35_reference["condition_producer_ea"] == 0x40A9FE
        assert row35_reference["predicate_anchor_ea"] == 0x40AA04
        assert row35_reference["predicate_kind"] == "slt"
        assert row35_reference["observed_predicate_kind"] == "sge"
        assert row35_reference["comparison_constant"] == 0x29947C85
        assert row35_reference["transfer_ea"] == 0x40AA10
        assert row35_reference["true_target_ea"] == 0x40AA12
        assert row35_reference["false_target_ea"] == 0x40B0BC
        assert row35_reference["true_target_block_id"] == "native@0x40AA12"
        assert row35_reference["false_target_block_id"] == "native@0x40B0BC"
        assert row35_reference["boundary_exit_eas"] == [0x40A5F0]
        row36_reference = reference_payloads["rhad:route@0x40AA2A"]
        assert row36_reference["reference_order"] == 36
        assert row36_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row36_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row36_reference["source_native_ea"] == 0x40AA12
        assert row36_reference["source_block_anchor_ea"] == 0x40AA26
        assert row36_reference["condition_producer_ea"] == 0x40AA18
        assert row36_reference["predicate_anchor_ea"] == 0x40AA1E
        assert row36_reference["predicate_kind"] == "eq"
        assert row36_reference["observed_predicate_kind"] == "ne"
        assert row36_reference["comparison_constant"] == 0x23B8E806
        assert row36_reference["transfer_ea"] == 0x40AA2A
        assert row36_reference["true_target_ea"] == 0x40AA2C
        assert row36_reference["false_target_ea"] == 0x40A5F0
        assert row36_reference["true_target_block_id"] == "native@0x40AA2C"
        assert row36_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row36_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row37_reference = reference_payloads["rhad:route@0x40AA5E"]
        assert row37_reference["reference_order"] == 37
        assert row37_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row37_reference["operation_variant"] == "cmov_selected_indirect"
        assert row37_reference["source_native_ea"] == 0x40AA3B
        assert row37_reference["source_block_anchor_ea"] == 0x40AA35
        assert row37_reference["condition_producer_ea"] == 0x40AA49
        assert row37_reference["predicate_anchor_ea"] == 0x40AA57
        assert row37_reference["predicate_kind"] == "slt"
        assert row37_reference["observed_predicate_kind"] == "sge"
        assert row37_reference["comparison_constant"] == 0x0BB2D365
        assert row37_reference["transfer_ea"] == 0x40AA5E
        assert row37_reference["true_target_ea"] == 0x40B6C0
        assert row37_reference["false_target_ea"] == 0x40A607
        assert row37_reference["true_target_block_id"] == "native@0x40B6C0"
        assert row37_reference["false_target_block_id"] == "native@0x40A607"
        assert row37_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row38_reference = reference_payloads["rhad:route@0x40AA78"]
        assert row38_reference["reference_order"] == 38
        assert row38_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row38_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row38_reference["source_native_ea"] == 0x40AA60
        assert row38_reference["source_block_anchor_ea"] == 0x40AA74
        assert row38_reference["join_ea"] == 0x40AA74
        assert row38_reference["condition_producer_ea"] == 0x40AA66
        assert row38_reference["predicate_anchor_ea"] == 0x40AA6C
        assert row38_reference["predicate_kind"] == "slt"
        assert row38_reference["observed_predicate_kind"] == "sge"
        assert row38_reference["comparison_constant"] == 0x7C4FB03D
        assert row38_reference["transfer_ea"] == 0x40AA78
        assert row38_reference["true_target_ea"] == 0x40AA7A
        assert row38_reference["false_target_ea"] == 0x40ADBE
        assert row38_reference["true_target_block_id"] == "native@0x40AA7A"
        assert row38_reference["false_target_block_id"] == "native@0x40ADBE"
        assert row38_reference["boundary_exit_eas"] == [
            0x40AA94,
            0x40ADD8,
            0x40B0F2,
            0x40B37C,
        ]
        row39_reference = reference_payloads["rhad:route@0x40AA92"]
        assert row39_reference["reference_order"] == 39
        assert row39_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row39_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row39_reference["source_native_ea"] == 0x40AA7A
        assert row39_reference["source_block_anchor_ea"] == 0x40AA88
        assert row39_reference["join_ea"] == 0x40AA8E
        assert row39_reference["condition_producer_ea"] == 0x40AA80
        assert row39_reference["predicate_anchor_ea"] == 0x40AA86
        assert row39_reference["predicate_kind"] == "slt"
        assert row39_reference["observed_predicate_kind"] == "sge"
        assert row39_reference["comparison_constant"] == 0x78BAC34B
        assert row39_reference["transfer_ea"] == 0x40AA92
        assert row39_reference["true_target_ea"] == 0x40AA94
        assert row39_reference["false_target_ea"] == 0x40B0F2
        assert row39_reference["true_target_block_id"] == "native@0x40AA94"
        assert row39_reference["false_target_block_id"] == "native@0x40B0F2"
        assert row39_reference["boundary_exit_eas"] == [0x40A5F0, 0x40AAAE]
        row40_reference = reference_payloads["rhad:route@0x40AAAC"]
        assert row40_reference["reference_order"] == 40
        assert row40_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row40_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row40_reference["source_native_ea"] == 0x40AA94
        assert row40_reference["source_block_anchor_ea"] == 0x40AAA2
        assert row40_reference["join_ea"] == 0x40AAA8
        assert row40_reference["condition_producer_ea"] == 0x40AA9A
        assert row40_reference["predicate_anchor_ea"] == 0x40AAA0
        assert row40_reference["predicate_kind"] == "eq"
        assert row40_reference["observed_predicate_kind"] == "ne"
        assert row40_reference["comparison_constant"] == 0x742F372A
        assert row40_reference["transfer_ea"] == 0x40AAAC
        assert row40_reference["true_target_ea"] == 0x40AAAE
        assert row40_reference["false_target_ea"] == 0x40A5F0
        assert row40_reference["true_target_block_id"] == "native@0x40AAAE"
        assert row40_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row40_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row42_reference = reference_payloads["route:rhad-direct@0x40AAFB"]
        assert row42_reference["reference_operation_id"] == "rhad:route@0x40AAFB"
        assert row42_reference["reference_order"] == 42
        assert row42_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row42_reference["operation_variant"] == "simple_indirect_jump"
        assert row42_reference["source_native_ea"] == 0x40A657
        assert row42_reference["source_block_anchor_ea"] == 0x40AAF1
        assert row42_reference["transfer_ea"] == 0x40AAFB
        assert row42_reference["direct_target_block_id"] == "native@0x40AAFD"
        assert row42_reference["owned_corridor_instruction_eas"] == [
            0x40A657,
            0x40AAF1,
            0x40AAF7,
            0x40AAF9,
            0x40AAFB,
        ]
        assert row42_reference["imported_closure_block_ids"] == [
            "native@0x40AAFD",
            "native@0x40AB0B",
            "native@0x40AB11",
            "native@0x40AB15",
        ]
        assert row42_reference["boundary_exit_eas"] == [0x40AB17, 0x40B149]
        row43_reference = reference_payloads["rhad:route@0x40AB15"]
        assert row43_reference["reference_order"] == 43
        assert row43_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row43_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row43_reference["source_native_ea"] == 0x40AAFD
        assert row43_reference["source_block_anchor_ea"] == 0x40AB0B
        assert row43_reference["join_ea"] == 0x40AB11
        assert row43_reference["condition_producer_ea"] == 0x40AB03
        assert row43_reference["predicate_anchor_ea"] == 0x40AB09
        assert row43_reference["predicate_kind"] == "slt"
        assert row43_reference["observed_predicate_kind"] == "sge"
        assert row43_reference["comparison_constant"] == 0x1EBFFA3C
        assert row43_reference["transfer_ea"] == 0x40AB15
        assert row43_reference["true_target_ea"] == 0x40AB17
        assert row43_reference["false_target_ea"] == 0x40B149
        assert row43_reference["true_target_block_id"] == "native@0x40AB17"
        assert row43_reference["false_target_block_id"] == "native@0x40B149"
        assert row43_reference["imported_closure_block_ids"] == [
            "native@0x40AB17",
            "native@0x40AB25",
            "native@0x40AB2B",
            "native@0x40AB2F",
            "native@0x40B149",
            "native@0x40B157",
            "native@0x40B15D",
            "native@0x40B161",
        ]
        assert row43_reference["boundary_exit_eas"] == [0x40A5F0, 0x40AB31]
        row44_reference = reference_payloads["rhad:route@0x40AB2F"]
        assert row44_reference["reference_order"] == 44
        assert row44_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row44_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row44_reference["source_native_ea"] == 0x40AB17
        assert row44_reference["source_block_anchor_ea"] == 0x40AB25
        assert row44_reference["join_ea"] == 0x40AB2B
        assert row44_reference["condition_producer_ea"] == 0x40AB1D
        assert row44_reference["predicate_anchor_ea"] == 0x40AB23
        assert row44_reference["predicate_kind"] == "eq"
        assert row44_reference["observed_predicate_kind"] == "ne"
        assert row44_reference["comparison_constant"] == 0x1BAABD04
        assert row44_reference["transfer_ea"] == 0x40AB2F
        assert row44_reference["true_target_ea"] == 0x40AB31
        assert row44_reference["false_target_ea"] == 0x40A5F0
        assert row44_reference["true_target_block_id"] == "native@0x40AB31"
        assert row44_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row44_reference["imported_closure_block_ids"] == [
            "native@0x40AB31",
            "native@0x40AB56",
            "native@0x40AB6A",
            "native@0x40AB74",
            "native@0x40B51B",
            "native@0x40B534",
            "native@0x40B540",
        ]
        assert row44_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row46_reference = reference_payloads["rhad:route@0x40AB8E"]
        assert row46_reference["reference_order"] == 46
        assert row46_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row46_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row46_reference["source_native_ea"] == 0x40AB76
        assert row46_reference["source_block_anchor_ea"] == 0x40AB84
        assert row46_reference["join_ea"] == 0x40AB8A
        assert row46_reference["condition_producer_ea"] == 0x40AB7C
        assert row46_reference["predicate_anchor_ea"] == 0x40AB82
        assert row46_reference["predicate_kind"] == "slt"
        assert row46_reference["observed_predicate_kind"] == "sge"
        assert row46_reference["comparison_constant"] == 0x456A4274
        assert row46_reference["transfer_ea"] == 0x40AB8E
        assert row46_reference["true_target_ea"] == 0x40AB90
        assert row46_reference["false_target_ea"] == 0x40B17F
        assert row46_reference["true_target_block_id"] == "native@0x40AB90"
        assert row46_reference["false_target_block_id"] == "native@0x40B17F"
        assert row46_reference["imported_closure_block_ids"] == [
            "native@0x40AB90",
            "native@0x40AB9E",
            "native@0x40ABA4",
            "native@0x40ABA8",
            "native@0x40B17F",
            "native@0x40B18D",
            "native@0x40B193",
            "native@0x40B197",
        ]
        assert row46_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40ABAA,
            0x40B199,
        ]
        row47_reference = reference_payloads["rhad:route@0x40ABA8"]
        assert row47_reference["reference_order"] == 47
        assert row47_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row47_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row47_reference["source_native_ea"] == 0x40AB90
        assert row47_reference["source_block_anchor_ea"] == 0x40AB9E
        assert row47_reference["join_ea"] == 0x40ABA4
        assert row47_reference["condition_producer_ea"] == 0x40AB96
        assert row47_reference["predicate_anchor_ea"] == 0x40AB9C
        assert row47_reference["predicate_kind"] == "eq"
        assert row47_reference["observed_predicate_kind"] == "ne"
        assert row47_reference["comparison_constant"] == 0x40D5B460
        assert row47_reference["transfer_ea"] == 0x40ABA8
        assert row47_reference["true_target_ea"] == 0x40ABAA
        assert row47_reference["false_target_ea"] == 0x40A5F0
        assert row47_reference["true_target_block_id"] == "native@0x40ABAA"
        assert row47_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row47_reference["imported_closure_block_ids"] == [
            "native@0x40ABAA",
            "native@0x40ABBD",
            "native@0x40ABC0",
            "native@0x40ABC4",
        ]
        assert row47_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row49_reference = reference_payloads["rhad:route@0x40ABDE"]
        assert row49_reference["reference_order"] == 49
        assert row49_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row49_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row49_reference["source_native_ea"] == 0x40ABC6
        assert row49_reference["source_block_anchor_ea"] == 0x40ABD4
        assert row49_reference["join_ea"] == 0x40ABDA
        assert row49_reference["condition_producer_ea"] == 0x40ABCC
        assert row49_reference["predicate_anchor_ea"] == 0x40ABD2
        assert row49_reference["predicate_kind"] == "slt"
        assert row49_reference["observed_predicate_kind"] == "sge"
        assert row49_reference["comparison_constant"] == 0x22C02855
        assert row49_reference["transfer_ea"] == 0x40ABDE
        assert row49_reference["true_target_ea"] == 0x40ABE0
        assert row49_reference["false_target_ea"] == 0x40B1D0
        assert row49_reference["true_target_block_id"] == "native@0x40ABE0"
        assert row49_reference["false_target_block_id"] == "native@0x40B1D0"
        assert row49_reference["imported_closure_block_ids"] == [
            "native@0x40ABE0",
            "native@0x40ABEE",
            "native@0x40ABF4",
            "native@0x40ABF8",
            "native@0x40B1D0",
            "native@0x40B1DE",
            "native@0x40B1E4",
            "native@0x40B1E8",
        ]
        assert row49_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40ABFA,
            0x40B1EA,
        ]
        row50_reference = reference_payloads["rhad:route@0x40ABF8"]
        assert row50_reference["reference_order"] == 50
        assert row50_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row50_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row50_reference["source_native_ea"] == 0x40ABE0
        assert row50_reference["source_block_anchor_ea"] == 0x40ABEE
        assert row50_reference["join_ea"] == 0x40ABF4
        assert row50_reference["condition_producer_ea"] == 0x40ABE6
        assert row50_reference["predicate_anchor_ea"] == 0x40ABEC
        assert row50_reference["predicate_kind"] == "eq"
        assert row50_reference["observed_predicate_kind"] == "ne"
        assert row50_reference["comparison_constant"] == 0x22642D96
        assert row50_reference["transfer_ea"] == 0x40ABF8
        assert row50_reference["true_target_ea"] == 0x40ABFA
        assert row50_reference["false_target_ea"] == 0x40A5F0
        assert row50_reference["true_target_block_id"] == "native@0x40ABFA"
        assert row50_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row50_reference["imported_closure_block_ids"] == [
            "native@0x40ABFA",
            "native@0x40ABFF",
            "native@0x40AC19",
            "native@0x40AC31",
            "native@0x40AC3B",
            "native@0x40B542",
            "native@0x40B55F",
            "native@0x40B56B",
        ]
        assert row50_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row51_reference = reference_payloads["route:rhad-direct@0x40AC3B"]
        assert row51_reference["reference_operation_id"] == "rhad:route@0x40AC3B"
        assert row51_reference["reference_order"] == 51
        assert row51_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row51_reference["operation_variant"] == "simple_indirect_jump"
        assert row51_reference["source_native_ea"] == 0x40AC19
        assert row51_reference["source_block_anchor_ea"] == 0x40AC31
        assert row51_reference["transfer_ea"] == 0x40AC3B
        assert row51_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row51_reference["boundary_exit_eas"] == [0x40B790]
        row52_reference = reference_payloads["rhad:route@0x40AC54"]
        assert row52_reference["reference_order"] == 52
        assert row52_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row52_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row52_reference["source_native_ea"] == 0x40AC3D
        assert row52_reference["source_block_anchor_ea"] == 0x40AC4A
        assert row52_reference["join_ea"] == 0x40AC50
        assert row52_reference["condition_producer_ea"] == 0x40AC42
        assert row52_reference["predicate_anchor_ea"] == 0x40AC48
        assert row52_reference["predicate_kind"] == "slt"
        assert row52_reference["observed_predicate_kind"] == "sge"
        assert row52_reference["comparison_constant"] == 0x7278AB7F
        assert row52_reference["transfer_ea"] == 0x40AC54
        assert row52_reference["true_target_ea"] == 0x40AC56
        assert row52_reference["false_target_ea"] == 0x40B21C
        assert row52_reference["true_target_block_id"] == "native@0x40AC56"
        assert row52_reference["false_target_block_id"] == "native@0x40B21C"
        assert row52_reference["owned_corridor_instruction_eas"] == [
            0x40AC3D,
            0x40AC42,
            0x40AC48,
            0x40AC4A,
            0x40AC50,
            0x40AC52,
            0x40AC54,
        ]
        assert row52_reference["imported_closure_block_ids"] == [
            "native@0x40AC56",
            "native@0x40AC64",
            "native@0x40AC6A",
            "native@0x40AC6E",
            "native@0x40B21C",
            "native@0x40B22A",
            "native@0x40B230",
            "native@0x40B234",
        ]
        assert row52_reference["boundary_exit_eas"] == [0x40A5F0, 0x40AC70]
        row53_reference = reference_payloads["rhad:route@0x40AC6E"]
        assert row53_reference["reference_order"] == 53
        assert row53_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row53_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row53_reference["source_native_ea"] == 0x40AC56
        assert row53_reference["source_block_anchor_ea"] == 0x40AC64
        assert row53_reference["join_ea"] == 0x40AC6A
        assert row53_reference["condition_producer_ea"] == 0x40AC5C
        assert row53_reference["predicate_anchor_ea"] == 0x40AC62
        assert row53_reference["predicate_kind"] == "eq"
        assert row53_reference["observed_predicate_kind"] == "ne"
        assert row53_reference["comparison_constant"] == 0x6D56E4D2
        assert row53_reference["transfer_ea"] == 0x40AC6E
        assert row53_reference["true_target_ea"] == 0x40AC70
        assert row53_reference["false_target_ea"] == 0x40A5F0
        assert row53_reference["true_target_block_id"] == "native@0x40AC70"
        assert row53_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row53_reference["owned_corridor_instruction_eas"] == [
            0x40AC56,
            0x40AC5C,
            0x40AC62,
            0x40AC64,
            0x40AC6A,
            0x40AC6C,
            0x40AC6E,
        ]
        assert row53_reference["imported_closure_block_ids"] == [
            "native@0x40AC70",
            "native@0x40AC81",
            "native@0x40AC9B",
            "native@0x40ACB3",
            "native@0x40ACBD",
            "native@0x40B56D",
            "native@0x40B58A",
            "native@0x40B596",
        ]
        assert row53_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row54_reference = reference_payloads["route:rhad-direct@0x40ACBD"]
        assert row54_reference["reference_operation_id"] == "rhad:route@0x40ACBD"
        assert row54_reference["reference_order"] == 54
        assert row54_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row54_reference["operation_variant"] == "simple_indirect_jump"
        assert row54_reference["source_native_ea"] == 0x40AC9B
        assert row54_reference["source_block_anchor_ea"] == 0x40ACB3
        assert row54_reference["transfer_ea"] == 0x40ACBD
        assert row54_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row54_reference["owned_corridor_instruction_eas"] == [
            0x40AC9B,
            0x40ACB3,
            0x40ACB5,
            0x40ACB7,
            0x40ACBD,
        ]
        assert row54_reference["boundary_exit_eas"] == [0x40B790]
        row55_reference = reference_payloads["rhad:route@0x40ACD7"]
        assert row55_reference["reference_order"] == 55
        assert row55_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row55_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row55_reference["source_native_ea"] == 0x40ACBF
        assert row55_reference["source_block_anchor_ea"] == 0x40ACD3
        assert row55_reference["join_ea"] == 0x40ACD3
        assert row55_reference["condition_producer_ea"] == 0x40ACC5
        assert row55_reference["predicate_anchor_ea"] == 0x40ACCB
        assert row55_reference["predicate_kind"] == "sge"
        assert row55_reference["observed_predicate_kind"] == "slt"
        assert row55_reference["comparison_constant"] == 0x13921E0E
        assert row55_reference["transfer_ea"] == 0x40ACD7
        assert row55_reference["true_target_ea"] == 0x40ACD9
        assert row55_reference["false_target_ea"] == 0x40B26D
        assert row55_reference["true_target_block_id"] == "native@0x40ACD9"
        assert row55_reference["false_target_block_id"] == "native@0x40B26D"
        assert row55_reference["owned_corridor_instruction_eas"] == [
            0x40ACBF,
            0x40ACC5,
            0x40ACCB,
            0x40ACCD,
            0x40ACD3,
            0x40ACD5,
            0x40ACD7,
        ]
        assert row55_reference["imported_closure_block_ids"] == [
            "native@0x40ACD9",
            "native@0x40ACE7",
            "native@0x40ACED",
            "native@0x40ACF1",
            "native@0x40B26D",
            "native@0x40B27B",
            "native@0x40B281",
            "native@0x40B285",
        ]
        assert row55_reference["boundary_exit_eas"] == [0x40A5F0, 0x40ACF3]
        row56_reference = reference_payloads["rhad:route@0x40ACF1"]
        assert row56_reference["reference_order"] == 56
        assert row56_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row56_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row56_reference["source_native_ea"] == 0x40ACD9
        assert row56_reference["source_block_anchor_ea"] == 0x40ACE7
        assert row56_reference["join_ea"] == 0x40ACED
        assert row56_reference["condition_producer_ea"] == 0x40ACDF
        assert row56_reference["predicate_anchor_ea"] == 0x40ACE5
        assert row56_reference["predicate_kind"] == "eq"
        assert row56_reference["observed_predicate_kind"] == "ne"
        assert row56_reference["comparison_constant"] == 0x0E9795EF
        assert row56_reference["transfer_ea"] == 0x40ACF1
        assert row56_reference["true_target_ea"] == 0x40ACF3
        assert row56_reference["false_target_ea"] == 0x40A5F0
        assert row56_reference["true_target_block_id"] == "native@0x40ACF3"
        assert row56_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row56_reference["owned_corridor_instruction_eas"] == [
            0x40ACD9,
            0x40ACDF,
            0x40ACE5,
            0x40ACE7,
            0x40ACED,
            0x40ACEF,
            0x40ACF1,
        ]
        assert row56_reference["imported_closure_block_ids"] == [
            "native@0x40ACF3",
            "native@0x40AD06",
            "native@0x40AD18",
            "native@0x40AD1C",
            "native@0x40B598",
            "native@0x40B5AF",
            "native@0x40B5B5",
        ]
        assert row56_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row57_reference = reference_payloads["route:rhad-direct@0x40AD1C"]
        assert row57_reference["reference_operation_id"] == "rhad:route@0x40AD1C"
        assert row57_reference["reference_order"] == 57
        assert row57_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row57_reference["operation_variant"] == "simple_indirect_jump"
        assert row57_reference["source_native_ea"] == 0x40AD06
        assert row57_reference["source_block_anchor_ea"] == 0x40AD18
        assert row57_reference["transfer_ea"] == 0x40AD1C
        assert row57_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row57_reference["owned_corridor_instruction_eas"] == [
            0x40AD06,
            0x40AD18,
            0x40AD1A,
            0x40AD1C,
        ]
        assert row57_reference["boundary_exit_eas"] == [0x40B790]
        row58_reference = reference_payloads["rhad:route@0x40AD36"]
        assert row58_reference["reference_order"] == 58
        assert row58_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row58_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row58_reference["source_native_ea"] == 0x40AD1E
        assert row58_reference["source_block_anchor_ea"] == 0x40AD32
        assert row58_reference["join_ea"] == 0x40AD32
        assert row58_reference["condition_producer_ea"] == 0x40AD24
        assert row58_reference["predicate_anchor_ea"] == 0x40AD2A
        assert row58_reference["predicate_kind"] == "sge"
        assert row58_reference["observed_predicate_kind"] == "slt"
        assert row58_reference["comparison_constant"] == 0x6487820D
        assert row58_reference["transfer_ea"] == 0x40AD36
        assert row58_reference["true_target_ea"] == 0x40AD38
        assert row58_reference["false_target_ea"] == 0x40B2DB
        assert row58_reference["true_target_block_id"] == "native@0x40AD38"
        assert row58_reference["false_target_block_id"] == "native@0x40B2DB"
        assert row58_reference["owned_corridor_instruction_eas"] == [
            0x40AD1E,
            0x40AD24,
            0x40AD2A,
            0x40AD2C,
            0x40AD32,
            0x40AD34,
            0x40AD36,
        ]
        assert row58_reference["imported_closure_block_ids"] == [
            "native@0x40AD38",
            "native@0x40AD46",
            "native@0x40AD4C",
            "native@0x40AD50",
            "native@0x40B2DB",
            "native@0x40B2E9",
            "native@0x40B2EF",
            "native@0x40B2F3",
        ]
        assert row58_reference["boundary_exit_eas"] == [0x40A5F0, 0x40AD52]
        row59_reference = reference_payloads["rhad:route@0x40AD50"]
        assert row59_reference["reference_order"] == 59
        assert row59_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row59_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row59_reference["source_native_ea"] == 0x40AD38
        assert row59_reference["source_block_anchor_ea"] == 0x40AD4C
        assert row59_reference["join_ea"] == 0x40AD4C
        assert row59_reference["condition_producer_ea"] == 0x40AD3E
        assert row59_reference["predicate_anchor_ea"] == 0x40AD44
        assert row59_reference["predicate_kind"] == "ne"
        assert row59_reference["observed_predicate_kind"] == "eq"
        assert row59_reference["comparison_constant"] == 0x636961E8
        assert row59_reference["transfer_ea"] == 0x40AD50
        assert row59_reference["true_target_ea"] == 0x40AD52
        assert row59_reference["false_target_ea"] == 0x40A5F0
        assert row59_reference["true_target_block_id"] == "native@0x40AD52"
        assert row59_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row59_reference["owned_corridor_instruction_eas"] == [
            0x40AD38,
            0x40AD3E,
            0x40AD44,
            0x40AD46,
            0x40AD4C,
            0x40AD4E,
            0x40AD50,
        ]
        assert row59_reference["imported_closure_block_ids"] == [
            "native@0x40AD52",
            "native@0x40AD65",
            "native@0x40AD68",
            "native@0x40AD6C",
        ]
        assert row59_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row60_reference = reference_payloads["rhad:route@0x40AD6C"]
        assert row60_reference["reference_order"] == 60
        assert row60_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row60_reference["operation_variant"] == "cmov_selected_indirect"
        assert row60_reference["source_native_ea"] == 0x40AD5D
        assert row60_reference["source_block_anchor_ea"] == 0x40AD52
        assert row60_reference["condition_producer_ea"] == 0x40AD57
        assert row60_reference["predicate_anchor_ea"] == 0x40AD65
        assert row60_reference["predicate_kind"] == "slt"
        assert row60_reference["observed_predicate_kind"] == "sge"
        assert row60_reference["comparison_constant"] == 0x0BB2D365
        assert row60_reference["transfer_ea"] == 0x40AD6C
        assert row60_reference["true_target_ea"] == 0x40B6C0
        assert row60_reference["false_target_ea"] == 0x40A607
        assert row60_reference["true_target_block_id"] == "native@0x40B6C0"
        assert row60_reference["false_target_block_id"] == "native@0x40A607"
        assert row60_reference["owned_corridor_instruction_eas"] == [
            0x40AD5D,
            0x40AD5F,
            0x40AD65,
            0x40AD68,
            0x40AD6A,
            0x40AD6C,
        ]
        assert row60_reference["imported_closure_block_ids"] == [
            "native@0x40A607",
            "native@0x40A615",
            "native@0x40A619",
            "native@0x40A680",
            "native@0x40A68A",
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row60_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row61_reference = reference_payloads["rhad:route@0x40AD86"]
        assert row61_reference["reference_order"] == 61
        assert row61_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row61_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row61_reference["source_native_ea"] == 0x40AD6E
        assert row61_reference["source_block_anchor_ea"] == 0x40AD82
        assert row61_reference["join_ea"] == 0x40AD82
        assert row61_reference["condition_producer_ea"] == 0x40AD74
        assert row61_reference["predicate_anchor_ea"] == 0x40AD7A
        assert row61_reference["predicate_kind"] == "sge"
        assert row61_reference["observed_predicate_kind"] == "slt"
        assert row61_reference["comparison_constant"] == 0x304E8694
        assert row61_reference["transfer_ea"] == 0x40AD86
        assert row61_reference["true_target_ea"] == 0x40AD88
        assert row61_reference["false_target_ea"] == 0x40B32C
        assert row61_reference["true_target_block_id"] == "native@0x40AD88"
        assert row61_reference["false_target_block_id"] == "native@0x40B32C"
        assert row61_reference["owned_corridor_instruction_eas"] == [
            0x40AD6E,
            0x40AD74,
            0x40AD7A,
            0x40AD7C,
            0x40AD82,
            0x40AD84,
            0x40AD86,
        ]
        assert row61_reference["imported_closure_block_ids"] == [
            "native@0x40AD88",
            "native@0x40AD96",
            "native@0x40AD9C",
            "native@0x40ADA0",
            "native@0x40B32C",
            "native@0x40B340",
        ]
        assert row61_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40ADA2,
            0x40B342,
        ]
        row62_reference = reference_payloads["rhad:route@0x40ADA0"]
        assert row62_reference["reference_order"] == 62
        assert row62_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row62_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row62_reference["source_native_ea"] == 0x40AD88
        assert row62_reference["source_block_anchor_ea"] == 0x40AD9C
        assert row62_reference["join_ea"] == 0x40AD9C
        assert row62_reference["condition_producer_ea"] == 0x40AD8E
        assert row62_reference["predicate_anchor_ea"] == 0x40AD94
        assert row62_reference["predicate_kind"] == "ne"
        assert row62_reference["observed_predicate_kind"] == "eq"
        assert row62_reference["comparison_constant"] == 0x2B8162DC
        assert row62_reference["transfer_ea"] == 0x40ADA0
        assert row62_reference["true_target_ea"] == 0x40ADA2
        assert row62_reference["false_target_ea"] == 0x40A5F0
        assert row62_reference["true_target_block_id"] == "native@0x40ADA2"
        assert row62_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row62_reference["owned_corridor_instruction_eas"] == [
            0x40AD88,
            0x40AD8E,
            0x40AD94,
            0x40AD96,
            0x40AD9C,
            0x40AD9E,
            0x40ADA0,
        ]
        assert row62_reference["imported_closure_block_ids"] == [
            "native@0x40ADA2",
            "native@0x40ADB5",
            "native@0x40ADB8",
            "native@0x40ADBC",
        ]
        assert row62_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row63_reference = reference_payloads["rhad:route@0x40ADBC"]
        assert row63_reference["reference_order"] == 63
        assert row63_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row63_reference["operation_variant"] == "cmov_selected_indirect"
        assert row63_reference["source_native_ea"] == 0x40ADAD
        assert row63_reference["source_block_anchor_ea"] == 0x40ADA2
        assert row63_reference["condition_producer_ea"] == 0x40ADA7
        assert row63_reference["predicate_anchor_ea"] == 0x40ADB5
        assert row63_reference["predicate_kind"] == "slt"
        assert row63_reference["observed_predicate_kind"] == "sge"
        assert row63_reference["comparison_constant"] == 0x0BB2D365
        assert row63_reference["transfer_ea"] == 0x40ADBC
        assert row63_reference["true_target_ea"] == 0x40B6C0
        assert row63_reference["false_target_ea"] == 0x40A607
        assert row63_reference["true_target_block_id"] == "native@0x40B6C0"
        assert row63_reference["false_target_block_id"] == "native@0x40A607"
        assert row63_reference["owned_corridor_instruction_eas"] == [
            0x40ADAD,
            0x40ADAF,
            0x40ADB5,
            0x40ADB8,
            0x40ADBA,
            0x40ADBC,
        ]
        assert row63_reference["imported_closure_block_ids"] == list(
            _IMPORTED_BLOCK_IDS[:9]
        )
        assert row63_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row64_reference = reference_payloads["rhad:route@0x40ADD6"]
        assert row64_reference["reference_order"] == 64
        assert row64_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row64_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row64_reference["source_native_ea"] == 0x40ADBE
        assert row64_reference["source_block_anchor_ea"] == 0x40ADD2
        assert row64_reference["join_ea"] == 0x40ADD2
        assert row64_reference["condition_producer_ea"] == 0x40ADC4
        assert row64_reference["predicate_anchor_ea"] == 0x40ADCA
        assert row64_reference["predicate_kind"] == "sge"
        assert row64_reference["observed_predicate_kind"] == "slt"
        assert row64_reference["comparison_constant"] == 0x7E46FA09
        assert row64_reference["transfer_ea"] == 0x40ADD6
        assert row64_reference["true_target_ea"] == 0x40ADD8
        assert row64_reference["false_target_ea"] == 0x40B37C
        assert row64_reference["true_target_block_id"] == "native@0x40ADD8"
        assert row64_reference["false_target_block_id"] == "native@0x40B37C"
        assert row64_reference["owned_corridor_instruction_eas"] == [
            0x40ADBE,
            0x40ADC4,
            0x40ADCA,
            0x40ADCC,
            0x40ADD2,
            0x40ADD4,
            0x40ADD6,
        ]
        assert row64_reference["imported_closure_block_ids"] == [
            "native@0x40ADD8",
            "native@0x40ADE6",
            "native@0x40ADEC",
            "native@0x40ADF0",
            "native@0x40B37C",
            "native@0x40B38A",
            "native@0x40B390",
            "native@0x40B394",
        ]
        assert row64_reference["boundary_exit_eas"] == [
            0x40A5F0,
            0x40ADF2,
            0x40B396,
            0x40B3E5,
        ]
        row65_reference = reference_payloads["rhad:route@0x40ADF0"]
        assert row65_reference["reference_order"] == 65
        assert row65_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row65_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row65_reference["source_native_ea"] == 0x40ADD8
        assert row65_reference["source_block_anchor_ea"] == 0x40ADEC
        assert row65_reference["join_ea"] == 0x40ADEC
        assert row65_reference["condition_producer_ea"] == 0x40ADDE
        assert row65_reference["predicate_anchor_ea"] == 0x40ADE4
        assert row65_reference["predicate_kind"] == "ne"
        assert row65_reference["observed_predicate_kind"] == "eq"
        assert row65_reference["comparison_constant"] == 0x7C4FB03D
        assert row65_reference["transfer_ea"] == 0x40ADF0
        assert row65_reference["true_target_ea"] == 0x40ADF2
        assert row65_reference["false_target_ea"] == 0x40A5F0
        assert row65_reference["true_target_block_id"] == "native@0x40ADF2"
        assert row65_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row65_reference["owned_corridor_instruction_eas"] == [
            0x40ADD8,
            0x40ADDE,
            0x40ADE4,
            0x40ADE6,
            0x40ADEC,
            0x40ADEE,
            0x40ADF0,
        ]
        assert row65_reference["imported_closure_block_ids"] == [
            "native@0x40ADF2",
            "native@0x40AE05",
            "native@0x40AE08",
            "native@0x40AE18",
        ]
        assert row65_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row66_reference = reference_payloads["rhad:route@0x40AE18"]
        assert row66_reference["reference_order"] == 66
        assert row66_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row66_reference["operation_variant"] == "cmov_selected_indirect"
        assert row66_reference["source_native_ea"] == 0x40ADFD
        assert row66_reference["source_block_anchor_ea"] == 0x40ADF2
        assert row66_reference["condition_producer_ea"] == 0x40ADF7
        assert row66_reference["predicate_anchor_ea"] == 0x40AE05
        assert row66_reference["predicate_kind"] == "slt"
        assert row66_reference["observed_predicate_kind"] == "sge"
        assert row66_reference["comparison_constant"] == 0x0BB2D365
        assert row66_reference["transfer_ea"] == 0x40AE18
        assert row66_reference["true_target_ea"] == 0x40B6C0
        assert row66_reference["false_target_ea"] == 0x40A607
        assert row66_reference["true_target_block_id"] == "native@0x40B6C0"
        assert row66_reference["false_target_block_id"] == "native@0x40A607"
        assert row66_reference["owned_corridor_instruction_eas"] == [
            0x40ADFD,
            0x40ADFF,
            0x40AE05,
            0x40AE08,
            0x40AE0A,
            0x40AE18,
        ]
        assert row66_reference["imported_closure_block_ids"] == list(
            _IMPORTED_BLOCK_IDS[:9]
        )
        assert row66_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row67_reference = reference_payloads["route:rhad-direct@0x40AE24"]
        assert row67_reference["reference_operation_id"] == "rhad:route@0x40AE24"
        assert row67_reference["reference_order"] == 67
        assert row67_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row67_reference["operation_variant"] == "simple_indirect_jump"
        assert row67_reference["source_native_ea"] == 0x40A66F
        assert row67_reference["source_block_anchor_ea"] == 0x40AE1A
        assert row67_reference["transfer_ea"] == 0x40AE24
        assert row67_reference["direct_target_block_id"] == "native@0x40A5CA"
        assert row67_reference["owned_corridor_instruction_eas"] == [
            0x40A66F,
            0x40AE1A,
            0x40AE20,
            0x40AE22,
            0x40AE24,
        ]
        assert row67_reference["imported_closure_block_ids"] == [
            "native@0x40A5CA",
            "native@0x40A5DC",
            "native@0x40A5DF",
            "native@0x40A5E3",
        ]
        assert row67_reference["boundary_exit_eas"] == [0x40A5F0, 0x40C898]
        row68_reference = reference_payloads["rhad:route@0x40AE3C"]
        assert row68_reference["reference_order"] == 68
        assert row68_reference["reference_symbol"] == (
            "JumpInliner._fixup_index_access"
        )
        assert row68_reference["operation_variant"] == "setcc_indexed_table"
        assert row68_reference["source_native_ea"] == 0x40AE26
        assert row68_reference["source_block_anchor_ea"] == 0x40AE26
        assert row68_reference["condition_producer_ea"] == 0x40AE28
        assert row68_reference["predicate_anchor_ea"] == 0x40AE2E
        assert row68_reference["predicate_kind"] == "eq"
        assert row68_reference["fallthrough_delivery"] == "planned_helper"
        assert row68_reference["transfer_ea"] == 0x40AE3C
        assert row68_reference["true_target_ea"] == 0x40AE3E
        assert row68_reference["false_target_ea"] == 0x40A5F0
        assert row68_reference["true_target_block_id"] == "native@0x40AE3E"
        assert row68_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row68_reference["owned_corridor_instruction_eas"] == [
            0x40AE26,
            0x40AE28,
            0x40AE2E,
            0x40AE31,
            0x40AE34,
            0x40AE3A,
            0x40AE3C,
        ]
        assert row68_reference["imported_closure_block_ids"] == [
            "native@0x40AE3E",
            "native@0x40AE63",
            "native@0x40AE82",
            "native@0x40AE85",
            "native@0x40AE89",
        ]
        assert row68_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row68_reference["setcc_table"]["table_base_ea"] == 0x48B650
        assert row68_reference["setcc_table"]["stride_bytes"] == 0x40
        assert row68_reference["setcc_table"]["index_scaling"] == {
            "kind": "explicit_shift",
            "shift_bits": 6,
            "shift_ea": 0x40AE31,
        }
        assert (
            row68_reference["proof_artifact"] == proof_artifacts["rhad:route@0x40AE3C"]
        )
        assert (
            row68_reference["aggregate_program_identity"]
            == (compiled_payload["aggregate_program_identity"])
        )
        row69_reference = reference_payloads["rhad:route@0x40AE89"]
        assert row69_reference["reference_order"] == 69
        assert row69_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row69_reference["operation_variant"] == "cmov_selected_indirect"
        assert row69_reference["source_native_ea"] == 0x40AE69
        assert row69_reference["source_block_anchor_ea"] == 0x40AE63
        assert row69_reference["condition_producer_ea"] == 0x40AE74
        assert row69_reference["predicate_anchor_ea"] == 0x40AE82
        assert row69_reference["predicate_kind"] == "slt"
        assert row69_reference["observed_predicate_kind"] == "sge"
        assert row69_reference["comparison_constant"] == 0x0BB2D365
        assert row69_reference["transfer_ea"] == 0x40AE89
        assert row69_reference["true_target_ea"] == 0x40B6C0
        assert row69_reference["false_target_ea"] == 0x40A607
        assert row69_reference["true_target_block_id"] == "native@0x40B6C0"
        assert row69_reference["false_target_block_id"] == "native@0x40A607"
        assert row69_reference["owned_corridor_instruction_eas"] == [
            0x40AE69,
            0x40AE7A,
            0x40AE7C,
            0x40AE82,
            0x40AE85,
            0x40AE87,
            0x40AE89,
        ]
        assert row69_reference["imported_closure_block_ids"] == list(
            _IMPORTED_BLOCK_IDS[:9]
        )
        assert row69_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        row70_reference = reference_payloads["rhad:route@0x40AEA3"]
        assert row70_reference["reference_order"] == 70
        assert row70_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row70_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row70_reference["source_native_ea"] == 0x40AE8B
        assert row70_reference["source_block_anchor_ea"] == 0x40AE9F
        assert row70_reference["join_ea"] == 0x40AE9F
        assert row70_reference["condition_producer_ea"] == 0x40AE91
        assert row70_reference["predicate_anchor_ea"] == 0x40AE97
        assert row70_reference["predicate_kind"] == "ne"
        assert row70_reference["observed_predicate_kind"] == "eq"
        assert row70_reference["comparison_constant"] == 0x40ABF871
        assert row70_reference["transfer_ea"] == 0x40AEA3
        assert row70_reference["true_target_ea"] == 0x40AEA5
        assert row70_reference["false_target_ea"] == 0x40A5F0
        assert row70_reference["true_target_block_id"] == "native@0x40AEA5"
        assert row70_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row70_reference["owned_corridor_instruction_eas"] == [
            0x40AE8B,
            0x40AE91,
            0x40AE97,
            0x40AE99,
            0x40AE9F,
            0x40AEA1,
            0x40AEA3,
        ]
        assert row70_reference["imported_closure_block_ids"] == [
            "native@0x40AEA5",
            "native@0x40AEC6",
            "native@0x40AEDA",
            "native@0x40AEE4",
            "native@0x40B5B7",
            "native@0x40B5D0",
            "native@0x40B5DC",
        ]
        assert row70_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row71_reference = reference_payloads["route:rhad-direct@0x40AEE4"]
        assert row71_reference["reference_operation_id"] == "rhad:route@0x40AEE4"
        assert row71_reference["reference_order"] == 71
        assert row71_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row71_reference["operation_variant"] == "simple_indirect_jump"
        assert row71_reference["source_native_ea"] == 0x40AEC6
        assert row71_reference["source_block_anchor_ea"] == 0x40AEDA
        assert row71_reference["transfer_ea"] == 0x40AEE4
        assert row71_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row71_reference["owned_corridor_instruction_eas"] == [
            0x40AEC6,
            0x40AEDA,
            0x40AEDC,
            0x40AEDE,
            0x40AEE4,
        ]
        assert row71_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row71_reference["boundary_exit_eas"] == [0x40B790]
        row72_reference = reference_payloads["rhad:route@0x40AEFE"]
        assert row72_reference["reference_order"] == 72
        assert row72_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row72_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row72_reference["source_native_ea"] == 0x40AEE6
        assert row72_reference["source_block_anchor_ea"] == 0x40AEFA
        assert row72_reference["join_ea"] == 0x40AEFA
        assert row72_reference["condition_producer_ea"] == 0x40AEEC
        assert row72_reference["predicate_anchor_ea"] == 0x40AEF2
        assert row72_reference["predicate_kind"] == "ne"
        assert row72_reference["observed_predicate_kind"] == "eq"
        assert row72_reference["comparison_constant"] == 0x2100AFDD
        assert row72_reference["transfer_ea"] == 0x40AEFE
        assert row72_reference["true_target_ea"] == 0x40AF00
        assert row72_reference["false_target_ea"] == 0x40A5F0
        assert row72_reference["true_target_block_id"] == "native@0x40AF00"
        assert row72_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row72_reference["owned_corridor_instruction_eas"] == [
            0x40AEE6,
            0x40AEEC,
            0x40AEF2,
            0x40AEF4,
            0x40AEFA,
            0x40AEFC,
            0x40AEFE,
        ]
        assert row72_reference["imported_closure_block_ids"] == [
            "native@0x40AF00",
            "native@0x40AF1C",
            "native@0x40AF2F",
            "native@0x40AF9D",
            "native@0x40AFBB",
            "native@0x40AFD3",
            "native@0x40AFDD",
            "native@0x40B5DE",
            "native@0x40B5FB",
            "native@0x40B607",
        ]
        assert row72_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row73_reference = reference_payloads["route:rhad-direct@0x40AFDD"]
        assert row73_reference["reference_operation_id"] == "rhad:route@0x40AFDD"
        assert row73_reference["reference_order"] == 73
        assert row73_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row73_reference["operation_variant"] == "simple_indirect_jump"
        assert row73_reference["source_native_ea"] == 0x40AFBB
        assert row73_reference["source_block_anchor_ea"] == 0x40AFD3
        assert row73_reference["transfer_ea"] == 0x40AFDD
        assert row73_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row73_reference["owned_corridor_instruction_eas"] == [
            0x40AFBB,
            0x40AFD3,
            0x40AFD5,
            0x40AFD7,
            0x40AFDD,
        ]
        assert row73_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row73_reference["boundary_exit_eas"] == [0x40B790]
        row74_reference = reference_payloads["rhad:route@0x40AFF7"]
        assert row74_reference["reference_order"] == 74
        assert row74_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row74_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row74_reference["source_native_ea"] == 0x40AFDF
        assert row74_reference["source_block_anchor_ea"] == 0x40AFF3
        assert row74_reference["join_ea"] == 0x40AFF3
        assert row74_reference["condition_producer_ea"] == 0x40AFE5
        assert row74_reference["predicate_anchor_ea"] == 0x40AFEB
        assert row74_reference["predicate_kind"] == "ne"
        assert row74_reference["observed_predicate_kind"] == "eq"
        assert row74_reference["comparison_constant"] == 0x6859ABF3
        assert row74_reference["transfer_ea"] == 0x40AFF7
        assert row74_reference["true_target_ea"] == 0x40AFF9
        assert row74_reference["false_target_ea"] == 0x40A5F0
        assert row74_reference["true_target_block_id"] == "native@0x40AFF9"
        assert row74_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row74_reference["owned_corridor_instruction_eas"] == [
            0x40AFDF,
            0x40AFE5,
            0x40AFEB,
            0x40AFED,
            0x40AFF3,
            0x40AFF5,
            0x40AFF7,
        ]
        assert row74_reference["imported_closure_block_ids"] == [
            "native@0x40AFF9",
            "native@0x40B00C",
            "native@0x40B01E",
            "native@0x40B022",
            "native@0x40B609",
            "native@0x40B620",
            "native@0x40B626",
        ]
        assert row74_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row75_reference = reference_payloads["route:rhad-direct@0x40B022"]
        assert row75_reference["reference_operation_id"] == "rhad:route@0x40B022"
        assert row75_reference["reference_order"] == 75
        assert row75_reference["operation_variant"] == "simple_indirect_jump"
        assert row75_reference["source_native_ea"] == 0x40B00C
        assert row75_reference["source_block_anchor_ea"] == 0x40B01E
        assert row75_reference["transfer_ea"] == 0x40B022
        assert row75_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row75_reference["owned_corridor_instruction_eas"] == [
            0x40B00C,
            0x40B01E,
            0x40B020,
            0x40B022,
        ]
        assert row75_reference["boundary_exit_eas"] == [0x40B790]
        row76_reference = reference_payloads["rhad:route@0x40B03C"]
        assert row76_reference["reference_order"] == 76
        assert row76_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row76_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row76_reference["source_native_ea"] == 0x40B024
        assert row76_reference["source_block_anchor_ea"] == 0x40B038
        assert row76_reference["join_ea"] == 0x40B038
        assert row76_reference["condition_producer_ea"] == 0x40B02A
        assert row76_reference["predicate_anchor_ea"] == 0x40B030
        assert row76_reference["predicate_kind"] == "ne"
        assert row76_reference["observed_predicate_kind"] == "eq"
        assert row76_reference["comparison_constant"] == 0x0CDF90C9
        assert row76_reference["transfer_ea"] == 0x40B03C
        assert row76_reference["true_target_ea"] == 0x40B03E
        assert row76_reference["false_target_ea"] == 0x40A5F0
        assert row76_reference["true_target_block_id"] == "native@0x40B03E"
        assert row76_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row76_reference["owned_corridor_instruction_eas"] == [
            0x40B024,
            0x40B02A,
            0x40B030,
            0x40B032,
            0x40B038,
            0x40B03A,
            0x40B03C,
        ]
        assert row76_reference["imported_closure_block_ids"] == [
            "native@0x40B03E",
            "native@0x40B059",
            "native@0x40B06B",
            "native@0x40B06F",
            "native@0x40B628",
            "native@0x40B63F",
            "native@0x40B645",
        ]
        assert row76_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row77_reference = reference_payloads["route:rhad-direct@0x40B06F"]
        assert row77_reference["reference_operation_id"] == "rhad:route@0x40B06F"
        assert row77_reference["reference_order"] == 77
        assert row77_reference["operation_variant"] == "simple_indirect_jump"
        assert row77_reference["source_native_ea"] == 0x40B059
        assert row77_reference["source_block_anchor_ea"] == 0x40B06B
        assert row77_reference["transfer_ea"] == 0x40B06F
        assert row77_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row77_reference["owned_corridor_instruction_eas"] == [
            0x40B059,
            0x40B06B,
            0x40B06D,
            0x40B06F,
        ]
        assert row77_reference["boundary_exit_eas"] == [0x40B790]
        row78_reference = reference_payloads["rhad:route@0x40B089"]
        assert row78_reference["reference_order"] == 78
        assert row78_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row78_reference["source_native_ea"] == 0x40B071
        assert row78_reference["source_block_anchor_ea"] == 0x40B085
        assert row78_reference["join_ea"] == 0x40B085
        assert row78_reference["condition_producer_ea"] == 0x40B077
        assert row78_reference["predicate_anchor_ea"] == 0x40B07D
        assert row78_reference["predicate_kind"] == "ne"
        assert row78_reference["observed_predicate_kind"] == "eq"
        assert row78_reference["comparison_constant"] == 0x5E07BA29
        assert row78_reference["transfer_ea"] == 0x40B089
        assert row78_reference["true_target_ea"] == 0x40B08B
        assert row78_reference["false_target_ea"] == 0x40A5F0
        assert row78_reference["owned_corridor_instruction_eas"] == [
            0x40B071,
            0x40B077,
            0x40B07D,
            0x40B07F,
            0x40B085,
            0x40B087,
            0x40B089,
        ]
        assert row78_reference["imported_closure_block_ids"] == [
            "native@0x40B08B",
            "native@0x40B094",
            "native@0x40B0B3",
            "native@0x40B0B6",
            "native@0x40B0BA",
        ]
        assert row78_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row79_reference = reference_payloads["rhad:route@0x40B0BA"]
        assert row79_reference["reference_order"] == 79
        assert row79_reference["reference_symbol"] == "JumpInliner._fixup_cmov"
        assert row79_reference["operation_variant"] == "cmov_selected_indirect"
        assert row79_reference["source_native_ea"] == 0x40B09A
        assert row79_reference["source_block_anchor_ea"] == 0x40B094
        assert row79_reference["condition_producer_ea"] == 0x40B0A5
        assert row79_reference["predicate_anchor_ea"] == 0x40B0B3
        assert row79_reference["predicate_kind"] == "slt"
        assert row79_reference["observed_predicate_kind"] == "sge"
        assert row79_reference["comparison_constant"] == 0x0BB2D365
        assert row79_reference["transfer_ea"] == 0x40B0BA
        assert row79_reference["true_target_ea"] == 0x40B6C0
        assert row79_reference["false_target_ea"] == 0x40A607
        assert row79_reference["owned_corridor_instruction_eas"] == [
            0x40B09A,
            0x40B0AB,
            0x40B0AD,
            0x40B0B3,
            0x40B0B6,
            0x40B0B8,
            0x40B0BA,
        ]
        assert row79_reference["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        setcc_reference = reference_payloads["rhad:route@0x40A77C"]
        assert setcc_reference["reference_order"] == 16
        assert setcc_reference["reference_symbol"] == (
            "JumpInliner._fixup_index_access"
        )
        assert setcc_reference["operation_variant"] == "setcc_indexed_table"
        assert setcc_reference["source_native_ea"] == 0x40A766
        assert setcc_reference["condition_producer_ea"] == 0x40A768
        assert setcc_reference["transfer_ea"] == 0x40A77C
        assert setcc_reference["true_target_ea"] == 0x40A77E
        assert setcc_reference["false_target_ea"] == 0x40ABC6
        assert setcc_reference["true_target_block_id"] == "native@0x40A77E"
        assert setcc_reference["false_target_block_id"] == "native@0x40ABC6"
        assert setcc_reference["setcc_table"]["table_base_ea"] == 0x48B81C
        assert setcc_reference["setcc_table"]["stride_bytes"] == 0x20
        assert setcc_reference["setcc_table"]["true_index"] == 1
        assert setcc_reference["setcc_table"]["false_index"] == 0
        assert (
            setcc_reference["proof_artifact"] == proof_artifacts["rhad:route@0x40A77C"]
        )
        assert (
            setcc_reference["aggregate_program_identity"]
            == (compiled_payload["aggregate_program_identity"])
        )
        scaled_setcc_reference = reference_payloads["rhad:route@0x40A792"]
        assert scaled_setcc_reference["reference_order"] == 17
        assert scaled_setcc_reference["reference_symbol"] == (
            "JumpInliner._fixup_index_access"
        )
        assert scaled_setcc_reference["operation_variant"] == ("setcc_indexed_table")
        assert scaled_setcc_reference["source_native_ea"] == 0x40A77E
        assert scaled_setcc_reference["condition_producer_ea"] == 0x40A780
        assert scaled_setcc_reference["predicate_anchor_ea"] == 0x40A786
        assert scaled_setcc_reference["predicate_kind"] == "sge"
        assert scaled_setcc_reference["transfer_ea"] == 0x40A792
        assert scaled_setcc_reference["true_target_ea"] == 0x40AEE6
        assert scaled_setcc_reference["false_target_ea"] == 0x40A794
        assert scaled_setcc_reference["true_target_block_id"] == ("native@0x40AEE6")
        assert scaled_setcc_reference["false_target_block_id"] == ("native@0x40A794")
        assert scaled_setcc_reference["setcc_table"]["table_base_ea"] == 0x48B4F8
        assert scaled_setcc_reference["setcc_table"]["stride_bytes"] == 8
        assert scaled_setcc_reference["setcc_table"]["index_scaling"] == {
            "kind": "scaled_lookup",
            "lookup_ea": 0x40A789,
            "scale_bytes": 8,
        }
        assert scaled_setcc_reference["setcc_table"]["true_index"] == 1
        assert scaled_setcc_reference["setcc_table"]["false_index"] == 0
        assert (
            scaled_setcc_reference["proof_artifact"]
            == proof_artifacts["rhad:route@0x40A792"]
        )
        assert (
            scaled_setcc_reference["aggregate_program_identity"]
            == compiled_payload["aggregate_program_identity"]
        )
        row18_reference = reference_payloads["rhad:route@0x40A7AC"]
        assert row18_reference["reference_order"] == 18
        assert row18_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row18_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert row18_reference["source_native_ea"] == 0x40A794
        assert row18_reference["condition_producer_ea"] == 0x40A79A
        assert row18_reference["predicate_anchor_ea"] == 0x40A7A0
        assert row18_reference["predicate_kind"] == "eq"
        assert row18_reference["observed_predicate_kind"] == "ne"
        assert row18_reference["transfer_ea"] == 0x40A7AC
        assert row18_reference["true_target_ea"] == 0x40A7AE
        assert row18_reference["false_target_ea"] == 0x40A5F0
        assert row18_reference["true_target_block_id"] == "native@0x40A7AE"
        assert row18_reference["false_target_block_id"] == "native@0x40A5F0"
        assert row18_reference["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        row19_reference = reference_payloads["route:rhad-direct@0x40A7EF"]
        assert row19_reference["reference_operation_id"] == "rhad:route@0x40A7EF"
        assert row19_reference["reference_order"] == 19
        assert row19_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert row19_reference["operation_variant"] == "simple_indirect_jump"
        assert row19_reference["source_native_ea"] == 0x40A7CD
        assert row19_reference["source_block_anchor_ea"] == 0x40A7E5
        assert row19_reference["transfer_ea"] == 0x40A7EF
        assert row19_reference["direct_target_block_id"] == "native@0x40B6C0"
        assert row19_reference["owned_corridor_instruction_eas"] == [
            0x40A7CD,
            0x40A7E5,
            0x40A7E7,
            0x40A7E9,
            0x40A7EF,
        ]
        assert row19_reference["imported_closure_block_ids"] == [
            "native@0x40B6C0",
            "native@0x40B6CA",
            "native@0x40B6D0",
            "native@0x40B6D4",
        ]
        assert row19_reference["boundary_exit_eas"] == [0x40B790]

        published_payload = json.loads(lifecycle_rows[2][3])
        assert (
            published_payload["aggregate_program_identity"]
            == (compiled_payload["aggregate_program_identity"])
        )
        assert published_payload["proof_artifact_identities"] == [
            row16_artifact_identity,
            row17_artifact_identity,
            row68_artifact_identity,
        ]

        maturity_payloads = {row[1]: json.loads(row[3]) for row in maturity_rows}
        for maturity in ("MMAT_GENERATED", "MMAT_PREOPTIMIZED", "MMAT_LOCOPT"):
            observations = {
                row["operation_id"]: row
                for row in maturity_payloads[maturity]["operation_observations"]
            }
            direct = observations["route:rhad-direct@0x40A619"]
            assert direct["source_present"] is True
            assert direct["source_topology_reachable"] is True
            assert direct["source_topology_retired"] is False
            assert direct["indirect_transfer_present"] is False
            assert direct["target_eas"] == [0x40A61B]
            assert direct["passed"] is True
            row3 = observations["route:rhad-direct@0x40A631"]
            assert row3["source_present"] is True
            assert row3["source_topology_reachable"] is True
            assert row3["source_topology_retired"] is False
            assert row3["indirect_transfer_present"] is False
            assert row3["target_eas"] == [0x40A633]
            assert row3["passed"] is True
            row4 = observations["route:rhad-direct@0x40A649"]
            assert row4["source_present"] is True
            assert row4["source_topology_reachable"] is True
            assert row4["source_topology_retired"] is False
            assert row4["indirect_transfer_present"] is False
            assert row4["target_eas"] == [0x40A8B5]
            assert row4["passed"] is True
            row5 = observations["route:rhad-direct@0x40A661"]
            assert row5["source_present"] is True
            assert row5["source_topology_reachable"] is True
            assert row5["source_topology_retired"] is False
            assert row5["indirect_transfer_present"] is False
            assert row5["target_eas"] == [0x40A663]
            assert row5["boundary_exit_eas"] == [
                0x40A5CA,
                0x40AAFD,
                0x40AE26,
            ]
            assert row5["passed"] is True
            row6 = observations["route:rhad-direct@0x40A679"]
            assert row6["source_present"] is False
            assert row6["source_topology_reachable"] is False
            assert row6["source_topology_retired"] is True
            assert row6["indirect_transfer_present"] is False
            assert row6["target_eas"] == []
            assert row6["boundary_exit_eas"] == [0x40A5F0, 0x40AE3E]
            assert row6["passed"] is True
            selected = observations["rhad:route@0x40A6A4"]
            assert selected["source_present"] is True
            assert selected["source_topology_reachable"] is True
            assert selected["source_topology_retired"] is False
            assert selected["indirect_transfer_present"] is False
            assert selected["target_eas"] == [0x40A6A6, 0x40A800]
            assert selected["semantic_target_eas"] == [0x40A6A6, 0x40A800]
            assert selected["delivery_target_eas"] == [0x40A6A6, 0x40A800]
            assert selected["semantic_targets_survive"] is True
            assert selected["passed"] is True
            row9 = observations["rhad:route@0x40A6BE"]
            assert row9["source_present"] is True
            assert row9["source_topology_reachable"] is True
            assert row9["source_topology_retired"] is False
            assert row9["indirect_transfer_present"] is False
            assert row9["target_eas"] == [0x40A6C0, 0x40A960]
            assert row9["semantic_target_eas"] == [0x40A6C0, 0x40A960]
            assert row9["delivery_target_eas"] == [0x40A6C0, 0x40A960]
            assert row9["semantic_targets_survive"] is True
            assert row9["passed"] is True
            row10 = observations["rhad:route@0x40A6D8"]
            assert row10["source_present"] is True
            assert row10["source_topology_reachable"] is True
            assert row10["source_topology_retired"] is False
            assert row10["indirect_transfer_present"] is False
            assert row10["target_eas"] == [0x40A6DA, 0x40AB76]
            assert row10["semantic_target_eas"] == [0x40A6DA, 0x40AB76]
            assert row10["delivery_target_eas"] == [0x40A6DA, 0x40AB76]
            assert row10["semantic_targets_survive"] is True
            assert row10["passed"] is True
            row11 = observations["rhad:route@0x40A6F2"]
            assert row11["source_present"] is True
            assert row11["source_topology_reachable"] is True
            assert row11["source_topology_retired"] is False
            assert row11["indirect_transfer_present"] is False
            assert row11["target_eas"] == [0x40A6F4, 0x40AE8B]
            assert row11["semantic_target_eas"] == [0x40A6F4, 0x40AE8B]
            assert row11["delivery_target_eas"] == [0x40A6F4, 0x40AE8B]
            assert row11["semantic_targets_survive"] is True
            assert row11["passed"] is True
            row12 = observations["rhad:route@0x40A70C"]
            assert row12["source_present"] is True
            assert row12["source_topology_reachable"] is True
            assert row12["source_topology_retired"] is False
            assert row12["indirect_transfer_present"] is False
            assert row12["target_eas"] == [0x40A5F0, 0x40A70E]
            assert row12["semantic_target_eas"] == [0x40A5F0, 0x40A70E]
            assert row12["delivery_target_eas"] == [0x40A5F0, 0x40A70E]
            assert row12["semantic_targets_survive"] is True
            assert row12["passed"] is True
            setcc = observations["rhad:route@0x40A77C"]
            assert setcc["source_present"] is True
            assert setcc["source_topology_reachable"] is True
            assert setcc["source_topology_retired"] is False
            assert setcc["indirect_transfer_present"] is False
            assert setcc["target_eas"] == [0x40A77E, 0x40ABC6]
            assert setcc["semantic_target_eas"] == [0x40A77E, 0x40ABC6]
            assert setcc["delivery_target_eas"] == [0x40A77E, 0x40ABC6]
            assert setcc["semantic_targets_survive"] is True
            assert setcc["passed"] is True
            scaled_setcc = observations["rhad:route@0x40A792"]
            assert scaled_setcc["source_present"] is True
            assert scaled_setcc["indirect_transfer_present"] is False
            assert scaled_setcc["semantic_target_eas"] == [0x40A794, 0x40AEE6]
            assert scaled_setcc["delivery_target_eas"] == [0x40A794, 0x40AEE6]
            assert scaled_setcc["semantic_targets_survive"] is True
            assert scaled_setcc["passed"] is True
            if maturity == "MMAT_GENERATED":
                assert scaled_setcc["source_topology_reachable"] is False
                assert scaled_setcc["source_topology_retired"] is True
                assert scaled_setcc["target_eas"] == [
                    0x40A5F0,
                    0x40A794,
                    0x40AEE6,
                ]
            else:
                assert scaled_setcc["source_topology_reachable"] is True
                assert scaled_setcc["source_topology_retired"] is False
                assert scaled_setcc["target_eas"] == [0x40A794, 0x40AEE6]
            row18 = observations["rhad:route@0x40A7AC"]
            assert row18["source_present"] is True
            assert row18["source_topology_reachable"] is True
            assert row18["source_topology_retired"] is False
            assert row18["indirect_transfer_present"] is False
            assert row18["target_eas"] == [0x40A5F0, 0x40A7AE]
            assert row18["semantic_target_eas"] == [0x40A5F0, 0x40A7AE]
            assert row18["delivery_target_eas"] == [0x40A5F0, 0x40A7AE]
            assert row18["semantic_targets_survive"] is True
            assert row18["passed"] is True
            row19 = observations["route:rhad-direct@0x40A7EF"]
            assert row19["source_present"] is True
            assert row19["source_topology_reachable"] is True
            assert row19["source_topology_retired"] is False
            assert row19["indirect_transfer_present"] is False
            assert row19["target_eas"] == [0x40B6C0]
            assert row19["boundary_exit_eas"] == [0x40B790]
            assert row19["passed"] is True
            row20 = observations["rhad:route@0x40A818"]
            assert row20["source_present"] is True
            assert row20["source_topology_reachable"] is True
            assert row20["source_topology_retired"] is False
            assert row20["indirect_transfer_present"] is False
            assert row20["target_eas"] == [0x40A81A, 0x40AA60]
            assert row20["semantic_target_eas"] == [0x40A81A, 0x40AA60]
            assert row20["delivery_target_eas"] == [0x40A81A, 0x40AA60]
            assert row20["semantic_targets_survive"] is True
            assert row20["passed"] is True
            row21 = observations["rhad:route@0x40A832"]
            assert row21["source_present"] is True
            assert row21["source_topology_reachable"] is True
            assert row21["source_topology_retired"] is False
            assert row21["indirect_transfer_present"] is False
            assert row21["target_eas"] == [0x40A834, 0x40AC3D]
            assert row21["semantic_target_eas"] == [0x40A834, 0x40AC3D]
            assert row21["delivery_target_eas"] == [0x40A834, 0x40AC3D]
            assert row21["semantic_targets_survive"] is True
            assert row21["passed"] is True
            row22 = observations["rhad:route@0x40A84C"]
            assert row22["source_present"] is True
            assert row22["source_topology_reachable"] is True
            assert row22["source_topology_retired"] is False
            assert row22["indirect_transfer_present"] is False
            assert row22["target_eas"] == [0x40A84E, 0x40AFDF]
            assert row22["semantic_target_eas"] == [0x40A84E, 0x40AFDF]
            assert row22["delivery_target_eas"] == [0x40A84E, 0x40AFDF]
            assert row22["semantic_targets_survive"] is True
            assert row22["passed"] is True
            row23 = observations["rhad:route@0x40A866"]
            assert row23["source_present"] is True
            assert row23["source_topology_reachable"] is True
            assert row23["source_topology_retired"] is False
            assert row23["indirect_transfer_present"] is False
            assert row23["target_eas"] == [0x40A5F0, 0x40A868]
            assert row23["semantic_target_eas"] == [0x40A5F0, 0x40A868]
            assert row23["delivery_target_eas"] == [0x40A5F0, 0x40A868]
            assert row23["semantic_targets_survive"] is True
            assert row23["passed"] is True
            row25 = observations["route:rhad-direct@0x40A8B3"]
            assert row25["source_present"] is True
            assert row25["source_topology_reachable"] is True
            assert row25["source_topology_retired"] is False
            assert row25["indirect_transfer_present"] is False
            assert row25["target_eas"] == [0x40A64B]
            assert row25["boundary_exit_eas"] == [0x40A663, 0x40AAFD]
            assert row25["passed"] is True
            row26 = observations["rhad:route@0x40A8CD"]
            assert row26["source_present"] is True
            assert row26["source_topology_reachable"] is True
            assert row26["source_topology_retired"] is False
            assert row26["indirect_transfer_present"] is False
            assert row26["target_eas"] == [0x40A8CF, 0x40ACBF]
            assert row26["semantic_target_eas"] == [0x40A8CF, 0x40ACBF]
            assert row26["delivery_target_eas"] == [0x40A8CF, 0x40ACBF]
            assert row26["semantic_targets_survive"] is True
            assert row26["passed"] is True
            row27 = observations["rhad:route@0x40A8E7"]
            assert row27["source_present"] is True
            assert row27["source_topology_reachable"] is True
            assert row27["source_topology_retired"] is False
            assert row27["indirect_transfer_present"] is False
            assert row27["target_eas"] == [0x40A8E9, 0x40B024]
            assert row27["semantic_target_eas"] == [0x40A8E9, 0x40B024]
            assert row27["delivery_target_eas"] == [0x40A8E9, 0x40B024]
            assert row27["semantic_targets_survive"] is True
            assert row27["passed"] is True
            row28 = observations["rhad:route@0x40A901"]
            assert row28["source_present"] is True
            assert row28["source_topology_reachable"] is True
            assert row28["source_topology_retired"] is False
            assert row28["indirect_transfer_present"] is False
            assert row28["target_eas"] == [0x40A5F0, 0x40A903]
            assert row28["semantic_target_eas"] == [0x40A5F0, 0x40A903]
            assert row28["delivery_target_eas"] == [0x40A5F0, 0x40A903]
            assert row28["semantic_targets_survive"] is True
            assert row28["passed"] is True
            row29 = observations["route:rhad-direct@0x40A95E"]
            assert row29["source_present"] is True
            assert row29["source_topology_reachable"] is True
            assert row29["source_topology_retired"] is False
            assert row29["indirect_transfer_present"] is False
            assert row29["target_eas"] == [0x40B6C0]
            assert row29["boundary_exit_eas"] == [0x40B790]
            assert row29["passed"] is True
            row30 = observations["rhad:route@0x40A978"]
            assert row30["source_present"] is True
            assert row30["source_topology_reachable"] is True
            assert row30["source_topology_retired"] is False
            assert row30["indirect_transfer_present"] is False
            assert row30["target_eas"] == [0x40A97A, 0x40AD1E]
            assert row30["semantic_target_eas"] == [0x40A97A, 0x40AD1E]
            assert row30["delivery_target_eas"] == [0x40A97A, 0x40AD1E]
            assert row30["semantic_targets_survive"] is True
            assert row30["passed"] is True
            row31 = observations["rhad:route@0x40A992"]
            assert row31["source_present"] is True
            assert row31["source_topology_reachable"] is True
            assert row31["source_topology_retired"] is False
            assert row31["indirect_transfer_present"] is False
            assert row31["target_eas"] == [0x40A994, 0x40B071]
            assert row31["semantic_target_eas"] == [0x40A994, 0x40B071]
            assert row31["delivery_target_eas"] == [0x40A994, 0x40B071]
            assert row31["semantic_targets_survive"] is True
            assert row31["passed"] is True
            row32 = observations["rhad:route@0x40A9AC"]
            assert row32["source_present"] is True
            assert row32["source_topology_reachable"] is True
            assert row32["source_topology_retired"] is False
            assert row32["indirect_transfer_present"] is False
            assert row32["target_eas"] == [0x40A5F0, 0x40A9AE]
            assert row32["semantic_target_eas"] == [0x40A5F0, 0x40A9AE]
            assert row32["delivery_target_eas"] == [0x40A5F0, 0x40A9AE]
            assert row32["semantic_targets_survive"] is True
            assert row32["passed"] is True
            row33 = observations["rhad:route@0x40A9DC"]
            assert row33["source_present"] is True
            assert row33["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row33["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row33["indirect_transfer_present"] is False
            assert row33["target_eas"] == (
                [0x40B6C0] if maturity == "MMAT_LOCOPT" else [0x40A607, 0x40B6C0]
            )
            assert row33["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row33["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row33["semantic_targets_survive"] is True
            assert row33["passed"] is True
            row34 = observations["rhad:route@0x40A9F6"]
            assert row34["source_present"] is True
            assert row34["source_topology_reachable"] is True
            assert row34["source_topology_retired"] is False
            assert row34["indirect_transfer_present"] is False
            assert row34["target_eas"] == [0x40A9F8, 0x40AD6E]
            assert row34["semantic_target_eas"] == [0x40A9F8, 0x40AD6E]
            assert row34["delivery_target_eas"] == [0x40A9F8, 0x40AD6E]
            assert row34["semantic_targets_survive"] is True
            assert row34["passed"] is True
            row35 = observations["rhad:route@0x40AA10"]
            assert row35["source_present"] is True
            assert row35["source_topology_reachable"] is True
            assert row35["source_topology_retired"] is False
            assert row35["indirect_transfer_present"] is False
            assert row35["target_eas"] == [0x40AA12, 0x40B0BC]
            assert row35["semantic_target_eas"] == [0x40AA12, 0x40B0BC]
            assert row35["delivery_target_eas"] == [0x40AA12, 0x40B0BC]
            assert row35["semantic_targets_survive"] is True
            assert row35["passed"] is True
            row36 = observations["rhad:route@0x40AA2A"]
            assert row36["source_present"] is True
            assert row36["source_topology_reachable"] is True
            assert row36["source_topology_retired"] is False
            assert row36["indirect_transfer_present"] is False
            assert row36["target_eas"] == [0x40A5F0, 0x40AA2C]
            assert row36["semantic_target_eas"] == [0x40A5F0, 0x40AA2C]
            assert row36["delivery_target_eas"] == [0x40A5F0, 0x40AA2C]
            assert row36["semantic_targets_survive"] is True
            assert row36["passed"] is True
            row37 = observations["rhad:route@0x40AA5E"]
            assert row37["source_present"] is True
            assert row37["source_topology_reachable"] is (maturity != "MMAT_LOCOPT")
            assert row37["source_topology_retired"] is (maturity == "MMAT_LOCOPT")
            assert row37["indirect_transfer_present"] is False
            assert row37["target_eas"] == (
                [0x40A607] if maturity == "MMAT_LOCOPT" else [0x40A607, 0x40B6C0]
            )
            assert row37["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row37["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row37["semantic_targets_survive"] is True
            assert row37["passed"] is True
            row38 = observations["rhad:route@0x40AA78"]
            assert row38["source_present"] is True
            assert row38["source_topology_reachable"] is True
            assert row38["source_topology_retired"] is False
            assert row38["indirect_transfer_present"] is False
            assert row38["target_eas"] == [0x40AA7A, 0x40ADBE]
            assert row38["semantic_target_eas"] == [0x40AA7A, 0x40ADBE]
            assert row38["delivery_target_eas"] == [0x40AA7A, 0x40ADBE]
            assert row38["semantic_targets_survive"] is True
            assert row38["passed"] is True
            row39 = observations["rhad:route@0x40AA92"]
            assert row39["source_present"] is True
            assert row39["source_topology_reachable"] is True
            assert row39["source_topology_retired"] is False
            assert row39["indirect_transfer_present"] is False
            assert row39["target_eas"] == [0x40AA94, 0x40B0F2]
            assert row39["semantic_target_eas"] == [0x40AA94, 0x40B0F2]
            assert row39["delivery_target_eas"] == [0x40AA94, 0x40B0F2]
            assert row39["semantic_targets_survive"] is True
            assert row39["passed"] is True
            row40 = observations["rhad:route@0x40AAAC"]
            assert row40["source_present"] is True
            assert row40["source_topology_reachable"] is True
            assert row40["source_topology_retired"] is False
            assert row40["indirect_transfer_present"] is False
            assert row40["target_eas"] == [0x40A5F0, 0x40AAAE]
            assert row40["semantic_target_eas"] == [0x40A5F0, 0x40AAAE]
            assert row40["delivery_target_eas"] == [0x40A5F0, 0x40AAAE]
            assert row40["semantic_targets_survive"] is True
            assert row40["passed"] is True
            row42 = observations["route:rhad-direct@0x40AAFB"]
            assert row42["source_present"] is True
            assert row42["source_topology_reachable"] is True
            assert row42["source_topology_retired"] is False
            assert row42["indirect_transfer_present"] is False
            assert row42["target_eas"] == [0x40AAFD]
            assert row42["boundary_exit_eas"] == [0x40AB17, 0x40B149]
            assert row42["passed"] is True
            row43 = observations["rhad:route@0x40AB15"]
            assert row43["source_present"] is True
            assert row43["source_topology_reachable"] is True
            assert row43["source_topology_retired"] is False
            assert row43["indirect_transfer_present"] is False
            assert row43["target_eas"] == [0x40AB17, 0x40B149]
            assert row43["semantic_target_eas"] == [0x40AB17, 0x40B149]
            assert row43["delivery_target_eas"] == [0x40AB17, 0x40B149]
            assert row43["semantic_targets_survive"] is True
            assert row43["passed"] is True
            row44 = observations["rhad:route@0x40AB2F"]
            assert row44["source_present"] is True
            assert row44["source_topology_reachable"] is True
            assert row44["source_topology_retired"] is False
            assert row44["indirect_transfer_present"] is False
            assert row44["target_eas"] == [0x40A5F0, 0x40AB31]
            assert row44["semantic_target_eas"] == [0x40A5F0, 0x40AB31]
            assert row44["delivery_target_eas"] == [0x40A5F0, 0x40AB31]
            assert row44["semantic_targets_survive"] is True
            assert row44["passed"] is True
            row46 = observations["rhad:route@0x40AB8E"]
            assert row46["source_present"] is True
            assert row46["source_topology_reachable"] is True
            assert row46["source_topology_retired"] is False
            assert row46["indirect_transfer_present"] is False
            assert row46["target_eas"] == [0x40AB90, 0x40B17F]
            assert row46["semantic_target_eas"] == [0x40AB90, 0x40B17F]
            assert row46["delivery_target_eas"] == [0x40AB90, 0x40B17F]
            assert row46["semantic_targets_survive"] is True
            assert row46["passed"] is True
            row47 = observations["rhad:route@0x40ABA8"]
            assert row47["source_present"] is True
            assert row47["source_topology_reachable"] is True
            assert row47["source_topology_retired"] is False
            assert row47["indirect_transfer_present"] is False
            assert row47["target_eas"] == [0x40A5F0, 0x40ABAA]
            assert row47["semantic_target_eas"] == [0x40A5F0, 0x40ABAA]
            assert row47["delivery_target_eas"] == [0x40A5F0, 0x40ABAA]
            assert row47["semantic_targets_survive"] is True
            assert row47["passed"] is True
            row49 = observations["rhad:route@0x40ABDE"]
            assert row49["source_present"] is True
            assert row49["source_topology_reachable"] is True
            assert row49["source_topology_retired"] is False
            assert row49["indirect_transfer_present"] is False
            assert row49["target_eas"] == [0x40ABE0, 0x40B1D0]
            assert row49["semantic_target_eas"] == [0x40ABE0, 0x40B1D0]
            assert row49["delivery_target_eas"] == [0x40ABE0, 0x40B1D0]
            assert row49["semantic_targets_survive"] is True
            assert row49["passed"] is True
            row50 = observations["rhad:route@0x40ABF8"]
            assert row50["source_present"] is True
            assert row50["source_topology_reachable"] is True
            assert row50["source_topology_retired"] is False
            assert row50["indirect_transfer_present"] is False
            assert row50["target_eas"] == [0x40A5F0, 0x40ABFA]
            assert row50["semantic_target_eas"] == [0x40A5F0, 0x40ABFA]
            assert row50["delivery_target_eas"] == [0x40A5F0, 0x40ABFA]
            assert row50["semantic_targets_survive"] is True
            assert row50["passed"] is True
            row51 = observations["route:rhad-direct@0x40AC3B"]
            assert row51["source_present"] is True
            assert row51["source_topology_reachable"] is True
            assert row51["source_topology_retired"] is False
            assert row51["indirect_transfer_present"] is False
            assert row51["target_eas"] == [0x40B6C0]
            assert row51["boundary_exit_eas"] == [0x40B790]
            assert row51["passed"] is True
            row52 = observations["rhad:route@0x40AC54"]
            assert row52["source_present"] is True
            assert row52["source_topology_reachable"] is True
            assert row52["source_topology_retired"] is False
            assert row52["indirect_transfer_present"] is False
            assert row52["target_eas"] == [0x40AC56, 0x40B21C]
            assert row52["semantic_target_eas"] == [0x40AC56, 0x40B21C]
            assert row52["delivery_target_eas"] == [0x40AC56, 0x40B21C]
            assert row52["semantic_targets_survive"] is True
            assert row52["passed"] is True
            row53 = observations["rhad:route@0x40AC6E"]
            assert row53["source_present"] is True
            assert row53["source_topology_reachable"] is True
            assert row53["source_topology_retired"] is False
            assert row53["indirect_transfer_present"] is False
            assert row53["target_eas"] == [0x40A5F0, 0x40AC70]
            assert row53["semantic_target_eas"] == [0x40A5F0, 0x40AC70]
            assert row53["delivery_target_eas"] == [0x40A5F0, 0x40AC70]
            assert row53["semantic_targets_survive"] is True
            assert row53["passed"] is True
            row54 = observations["route:rhad-direct@0x40ACBD"]
            assert row54["source_present"] is True
            assert row54["source_topology_reachable"] is True
            assert row54["source_topology_retired"] is False
            assert row54["indirect_transfer_present"] is False
            assert row54["target_eas"] == [0x40B6C0]
            assert row54["boundary_exit_eas"] == [0x40B790]
            assert row54["passed"] is True
            row55 = observations["rhad:route@0x40ACD7"]
            assert row55["source_present"] is True
            assert row55["source_topology_reachable"] is True
            assert row55["source_topology_retired"] is False
            assert row55["indirect_transfer_present"] is False
            assert row55["target_eas"] == [0x40ACD9, 0x40B26D]
            assert row55["semantic_target_eas"] == [0x40ACD9, 0x40B26D]
            assert row55["delivery_target_eas"] == [0x40ACD9, 0x40B26D]
            assert row55["semantic_targets_survive"] is True
            assert row55["passed"] is True
            row56 = observations["rhad:route@0x40ACF1"]
            assert row56["source_present"] is True
            assert row56["source_topology_reachable"] is True
            assert row56["source_topology_retired"] is False
            assert row56["indirect_transfer_present"] is False
            assert row56["target_eas"] == [0x40A5F0, 0x40ACF3]
            assert row56["semantic_target_eas"] == [0x40A5F0, 0x40ACF3]
            assert row56["delivery_target_eas"] == [0x40A5F0, 0x40ACF3]
            assert row56["semantic_targets_survive"] is True
            assert row56["passed"] is True
            row57 = observations["route:rhad-direct@0x40AD1C"]
            assert row57["source_present"] is True
            assert row57["source_topology_reachable"] is True
            assert row57["source_topology_retired"] is False
            assert row57["indirect_transfer_present"] is False
            assert row57["target_eas"] == [0x40B6C0]
            assert row57["boundary_exit_eas"] == [0x40B790]
            assert row57["passed"] is True
            row58 = observations["rhad:route@0x40AD36"]
            assert row58["source_present"] is True
            assert row58["source_topology_reachable"] is True
            assert row58["source_topology_retired"] is False
            assert row58["indirect_transfer_present"] is False
            assert row58["target_eas"] == [0x40AD38, 0x40B2DB]
            assert row58["semantic_target_eas"] == [0x40AD38, 0x40B2DB]
            assert row58["delivery_target_eas"] == [0x40AD38, 0x40B2DB]
            assert row58["semantic_targets_survive"] is True
            assert row58["passed"] is True
            row59 = observations["rhad:route@0x40AD50"]
            assert row59["source_present"] is True
            assert row59["source_topology_reachable"] is True
            assert row59["source_topology_retired"] is False
            assert row59["indirect_transfer_present"] is False
            assert row59["target_eas"] == [0x40A5F0, 0x40AD52]
            assert row59["semantic_target_eas"] == [0x40A5F0, 0x40AD52]
            assert row59["delivery_target_eas"] == [0x40A5F0, 0x40AD52]
            assert row59["semantic_targets_survive"] is True
            assert row59["passed"] is True
            row60 = observations["rhad:route@0x40AD6C"]
            assert row60["source_present"] is True
            assert row60["indirect_transfer_present"] is False
            assert row60["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row60["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row60["semantic_targets_survive"] is True
            assert row60["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row60["source_topology_reachable"] is False
                assert row60["source_topology_retired"] is True
                assert row60["target_eas"] == [0x40B6C0]
            else:
                assert row60["source_topology_reachable"] is True
                assert row60["source_topology_retired"] is False
                assert row60["target_eas"] == [0x40A607, 0x40B6C0]
            row61 = observations["rhad:route@0x40AD86"]
            assert row61["source_present"] is True
            assert row61["source_topology_reachable"] is True
            assert row61["source_topology_retired"] is False
            assert row61["indirect_transfer_present"] is False
            assert row61["target_eas"] == [0x40AD88, 0x40B32C]
            assert row61["semantic_target_eas"] == [0x40AD88, 0x40B32C]
            assert row61["delivery_target_eas"] == [0x40AD88, 0x40B32C]
            assert row61["semantic_targets_survive"] is True
            assert row61["passed"] is True
            row62 = observations["rhad:route@0x40ADA0"]
            assert row62["source_present"] is True
            assert row62["source_topology_reachable"] is True
            assert row62["source_topology_retired"] is False
            assert row62["indirect_transfer_present"] is False
            assert row62["target_eas"] == [0x40A5F0, 0x40ADA2]
            assert row62["semantic_target_eas"] == [0x40A5F0, 0x40ADA2]
            assert row62["delivery_target_eas"] == [0x40A5F0, 0x40ADA2]
            assert row62["semantic_targets_survive"] is True
            assert row62["passed"] is True
            row63 = observations["rhad:route@0x40ADBC"]
            assert row63["source_present"] is True
            assert row63["indirect_transfer_present"] is False
            assert row63["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row63["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row63["semantic_targets_survive"] is True
            assert row63["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row63["source_topology_reachable"] is False
                assert row63["source_topology_retired"] is True
                assert row63["target_eas"] == [0x40A607]
            else:
                assert row63["source_topology_reachable"] is True
                assert row63["source_topology_retired"] is False
                assert row63["target_eas"] == [0x40A607, 0x40B6C0]
            row64 = observations["rhad:route@0x40ADD6"]
            assert row64["source_present"] is True
            assert row64["source_topology_reachable"] is True
            assert row64["source_topology_retired"] is False
            assert row64["indirect_transfer_present"] is False
            assert row64["target_eas"] == [0x40ADD8, 0x40B37C]
            assert row64["semantic_target_eas"] == [0x40ADD8, 0x40B37C]
            assert row64["delivery_target_eas"] == [0x40ADD8, 0x40B37C]
            assert row64["semantic_targets_survive"] is True
            assert row64["passed"] is True
            row65 = observations["rhad:route@0x40ADF0"]
            assert row65["source_present"] is True
            assert row65["source_topology_reachable"] is True
            assert row65["source_topology_retired"] is False
            assert row65["indirect_transfer_present"] is False
            assert row65["target_eas"] == [0x40A5F0, 0x40ADF2]
            assert row65["semantic_target_eas"] == [0x40A5F0, 0x40ADF2]
            assert row65["delivery_target_eas"] == [0x40A5F0, 0x40ADF2]
            assert row65["semantic_targets_survive"] is True
            assert row65["passed"] is True
            row66 = observations["rhad:route@0x40AE18"]
            assert row66["source_present"] is True
            assert row66["indirect_transfer_present"] is False
            assert row66["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row66["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row66["semantic_targets_survive"] is True
            assert row66["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row66["source_topology_reachable"] is False
                assert row66["source_topology_retired"] is True
                assert row66["target_eas"] == [0x40A607]
            else:
                assert row66["source_topology_reachable"] is True
                assert row66["source_topology_retired"] is False
                assert row66["target_eas"] == [0x40A607, 0x40B6C0]
            row67 = observations["route:rhad-direct@0x40AE24"]
            assert row67["indirect_transfer_present"] is False
            assert row67["boundary_exit_eas"] == [0x40A5F0, 0x40C898]
            assert row67["passed"] is True
            assert row67["source_present"] is True
            assert row67["source_topology_reachable"] is True
            assert row67["source_topology_retired"] is False
            assert row67["target_eas"] == [0x40A5CA]
            row68 = observations["rhad:route@0x40AE3C"]
            assert row68["source_present"] is True
            assert row68["source_topology_reachable"] is True
            assert row68["source_topology_retired"] is False
            assert row68["indirect_transfer_present"] is False
            assert row68["target_eas"] == [0x40A5F0, 0x40AE3E]
            assert row68["semantic_target_eas"] == [0x40A5F0, 0x40AE3E]
            assert row68["delivery_target_eas"] == [0x40A5F0, 0x40AE3E]
            assert row68["semantic_targets_survive"] is True
            assert row68["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row68["passed"] is True
            row69 = observations["rhad:route@0x40AE89"]
            assert row69["source_present"] is True
            assert row69["indirect_transfer_present"] is False
            assert row69["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row69["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row69["semantic_targets_survive"] is True
            assert row69["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row69["source_topology_reachable"] is False
                assert row69["source_topology_retired"] is True
                assert row69["target_eas"] == [0x40B6C0]
            else:
                assert row69["source_topology_reachable"] is True
                assert row69["source_topology_retired"] is False
                assert row69["target_eas"] == [0x40A607, 0x40B6C0]
            row70 = observations["rhad:route@0x40AEA3"]
            assert row70["source_present"] is True
            assert row70["source_topology_reachable"] is True
            assert row70["source_topology_retired"] is False
            assert row70["indirect_transfer_present"] is False
            assert row70["target_eas"] == [0x40A5F0, 0x40AEA5]
            assert row70["semantic_target_eas"] == [0x40A5F0, 0x40AEA5]
            assert row70["delivery_target_eas"] == [0x40A5F0, 0x40AEA5]
            assert row70["semantic_targets_survive"] is True
            assert row70["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row70["passed"] is True
            row71 = observations["route:rhad-direct@0x40AEE4"]
            assert row71["source_present"] is True
            assert row71["source_topology_reachable"] is True
            assert row71["source_topology_retired"] is False
            assert row71["indirect_transfer_present"] is False
            assert row71["target_eas"] == [0x40B6C0]
            assert row71["boundary_exit_eas"] == [0x40B790]
            assert row71["passed"] is True
            row72 = observations["rhad:route@0x40AEFE"]
            assert row72["source_present"] is True
            assert row72["source_topology_reachable"] is True
            assert row72["source_topology_retired"] is False
            assert row72["indirect_transfer_present"] is False
            assert row72["target_eas"] == [0x40A5F0, 0x40AF00]
            assert row72["semantic_target_eas"] == [0x40A5F0, 0x40AF00]
            assert row72["delivery_target_eas"] == [0x40A5F0, 0x40AF00]
            assert row72["semantic_targets_survive"] is True
            assert row72["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row72["passed"] is True
            row73 = observations["route:rhad-direct@0x40AFDD"]
            assert row73["source_present"] is True
            assert row73["source_topology_reachable"] is True
            assert row73["source_topology_retired"] is False
            assert row73["indirect_transfer_present"] is False
            assert row73["target_eas"] == [0x40B6C0]
            assert row73["boundary_exit_eas"] == [0x40B790]
            assert row73["passed"] is True
            row74 = observations["rhad:route@0x40AFF7"]
            assert row74["source_present"] is True
            assert row74["source_topology_reachable"] is True
            assert row74["source_topology_retired"] is False
            assert row74["indirect_transfer_present"] is False
            assert row74["target_eas"] == [0x40A5F0, 0x40AFF9]
            assert row74["semantic_target_eas"] == [0x40A5F0, 0x40AFF9]
            assert row74["delivery_target_eas"] == [0x40A5F0, 0x40AFF9]
            assert row74["semantic_targets_survive"] is True
            assert row74["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row74["passed"] is True
            row75 = observations["route:rhad-direct@0x40B022"]
            assert row75["source_present"] is True
            assert row75["source_topology_reachable"] is True
            assert row75["source_topology_retired"] is False
            assert row75["indirect_transfer_present"] is False
            assert row75["target_eas"] == [0x40B6C0]
            assert row75["boundary_exit_eas"] == [0x40B790]
            assert row75["passed"] is True
            row76 = observations["rhad:route@0x40B03C"]
            assert row76["source_present"] is True
            assert row76["source_topology_reachable"] is True
            assert row76["source_topology_retired"] is False
            assert row76["indirect_transfer_present"] is False
            assert row76["target_eas"] == [0x40A5F0, 0x40B03E]
            assert row76["semantic_target_eas"] == [0x40A5F0, 0x40B03E]
            assert row76["delivery_target_eas"] == [0x40A5F0, 0x40B03E]
            assert row76["semantic_targets_survive"] is True
            assert row76["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row76["passed"] is True
            row77 = observations["route:rhad-direct@0x40B06F"]
            assert row77["source_present"] is True
            assert row77["source_topology_reachable"] is True
            assert row77["source_topology_retired"] is False
            assert row77["indirect_transfer_present"] is False
            assert row77["target_eas"] == [0x40B6C0]
            assert row77["boundary_exit_eas"] == [0x40B790]
            assert row77["passed"] is True
            row78 = observations["rhad:route@0x40B089"]
            assert row78["source_present"] is True
            assert row78["source_topology_reachable"] is True
            assert row78["source_topology_retired"] is False
            assert row78["indirect_transfer_present"] is False
            assert row78["target_eas"] == [0x40A5F0, 0x40B08B]
            assert row78["semantic_target_eas"] == [0x40A5F0, 0x40B08B]
            assert row78["delivery_target_eas"] == [0x40A5F0, 0x40B08B]
            assert row78["semantic_targets_survive"] is True
            assert row78["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
            assert row78["passed"] is True
            row79 = observations["rhad:route@0x40B0BA"]
            assert row79["source_present"] is True
            assert row79["indirect_transfer_present"] is False
            assert row79["semantic_target_eas"] == [0x40A607, 0x40B6C0]
            assert row79["delivery_target_eas"] == [0x40A607, 0x40B6C0]
            assert row79["semantic_targets_survive"] is True
            assert row79["boundary_exit_eas"] == [
                0x40A61B,
                0x40A68C,
                0x40B790,
            ]
            assert row79["passed"] is True
            if maturity == "MMAT_LOCOPT":
                assert row79["source_topology_reachable"] is False
                assert row79["source_topology_retired"] is True
                assert row79["target_eas"] == [0x40A607]
            else:
                assert row79["source_topology_reachable"] is True
                assert row79["source_topology_retired"] is False
                assert row79["target_eas"] == [0x40A607, 0x40B6C0]
        calls_payload = maturity_payloads["MMAT_CALLS"]
        calls_observations = {
            row["operation_id"]: row for row in calls_payload["operation_observations"]
        }
        direct_calls = calls_observations["route:rhad-direct@0x40A619"]
        assert direct_calls["source_present"] is False
        assert direct_calls["source_topology_reachable"] is False
        assert direct_calls["source_topology_retired"] is True
        assert direct_calls["indirect_transfer_present"] is False
        assert direct_calls["target_eas"] == []
        assert direct_calls["passed"] is True
        row3_calls = calls_observations["route:rhad-direct@0x40A631"]
        assert row3_calls["source_present"] is False
        assert row3_calls["source_topology_reachable"] is False
        assert row3_calls["source_topology_retired"] is True
        assert row3_calls["indirect_transfer_present"] is False
        assert row3_calls["target_eas"] == []
        assert row3_calls["passed"] is True
        row4_calls = calls_observations["route:rhad-direct@0x40A649"]
        assert row4_calls["source_present"] is False
        assert row4_calls["source_topology_reachable"] is False
        assert row4_calls["source_topology_retired"] is True
        assert row4_calls["indirect_transfer_present"] is False
        assert row4_calls["target_eas"] == []
        assert row4_calls["passed"] is True
        row5_calls = calls_observations["route:rhad-direct@0x40A661"]
        assert row5_calls["source_present"] is False
        assert row5_calls["source_topology_reachable"] is False
        assert row5_calls["source_topology_retired"] is True
        assert row5_calls["indirect_transfer_present"] is False
        assert row5_calls["target_eas"] == []
        assert row5_calls["boundary_exit_eas"] == [
            0x40A5CA,
            0x40AAFD,
            0x40AE26,
        ]
        assert row5_calls["passed"] is True
        row6_calls = calls_observations["route:rhad-direct@0x40A679"]
        assert row6_calls["source_present"] is False
        assert row6_calls["source_topology_reachable"] is False
        assert row6_calls["source_topology_retired"] is True
        assert row6_calls["indirect_transfer_present"] is False
        assert row6_calls["target_eas"] == []
        assert row6_calls["boundary_exit_eas"] == [0x40A5F0, 0x40AE3E]
        assert row6_calls["passed"] is True
        accepted_calls = calls_observations["rhad:route@0x40A605"]
        assert accepted_calls["indirect_transfer_present"] is False
        assert accepted_calls["passed"] is True
        selected_calls = calls_observations["rhad:route@0x40A6A4"]
        assert selected_calls["source_present"] is False
        assert selected_calls["source_topology_reachable"] is False
        assert selected_calls["source_topology_retired"] is True
        assert selected_calls["indirect_transfer_present"] is False
        assert selected_calls["target_eas"] == []
        assert selected_calls["semantic_target_eas"] == [0x40A6A6, 0x40A800]
        assert selected_calls["delivery_target_eas"] == [0x40A6A6, 0x40A800]
        assert selected_calls["semantic_targets_survive"] is True
        assert selected_calls["passed"] is True
        row9_calls = calls_observations["rhad:route@0x40A6BE"]
        assert row9_calls["source_present"] is False
        assert row9_calls["source_topology_reachable"] is False
        assert row9_calls["source_topology_retired"] is True
        assert row9_calls["indirect_transfer_present"] is False
        assert row9_calls["target_eas"] == []
        assert row9_calls["semantic_target_eas"] == [0x40A6C0, 0x40A960]
        assert row9_calls["delivery_target_eas"] == [0x40A6C0, 0x40A960]
        assert row9_calls["semantic_targets_survive"] is True
        assert row9_calls["passed"] is True
        row10_calls = calls_observations["rhad:route@0x40A6D8"]
        assert row10_calls["source_present"] is False
        assert row10_calls["source_topology_reachable"] is False
        assert row10_calls["source_topology_retired"] is True
        assert row10_calls["indirect_transfer_present"] is False
        assert row10_calls["target_eas"] == []
        assert row10_calls["semantic_target_eas"] == [0x40A6DA, 0x40AB76]
        assert row10_calls["delivery_target_eas"] == [0x40A6DA, 0x40AB76]
        assert row10_calls["semantic_targets_survive"] is True
        assert row10_calls["passed"] is True
        row11_calls = calls_observations["rhad:route@0x40A6F2"]
        assert row11_calls["source_present"] is False
        assert row11_calls["source_topology_reachable"] is False
        assert row11_calls["source_topology_retired"] is True
        assert row11_calls["indirect_transfer_present"] is False
        assert row11_calls["target_eas"] == []
        assert row11_calls["semantic_target_eas"] == [0x40A6F4, 0x40AE8B]
        assert row11_calls["delivery_target_eas"] == [0x40A6F4, 0x40AE8B]
        assert row11_calls["semantic_targets_survive"] is True
        assert row11_calls["passed"] is True
        row12_calls = calls_observations["rhad:route@0x40A70C"]
        assert row12_calls["source_present"] is False
        assert row12_calls["source_topology_reachable"] is False
        assert row12_calls["source_topology_retired"] is True
        assert row12_calls["indirect_transfer_present"] is False
        assert row12_calls["target_eas"] == []
        assert row12_calls["semantic_target_eas"] == [0x40A5F0, 0x40A70E]
        assert row12_calls["delivery_target_eas"] == [0x40A5F0, 0x40A70E]
        assert row12_calls["semantic_targets_survive"] is True
        assert row12_calls["passed"] is True
        setcc_calls = calls_observations["rhad:route@0x40A77C"]
        assert setcc_calls["source_present"] is True
        assert setcc_calls["source_topology_reachable"] is True
        assert setcc_calls["source_topology_retired"] is False
        assert setcc_calls["indirect_transfer_present"] is False
        assert setcc_calls["target_eas"] == [0x40A77E, 0x40ABC6]
        assert setcc_calls["semantic_target_eas"] == [0x40A77E, 0x40ABC6]
        assert setcc_calls["delivery_target_eas"] == [0x40A77E, 0x40ABC6]
        assert setcc_calls["semantic_targets_survive"] is True
        assert setcc_calls["passed"] is True
        scaled_setcc_calls = calls_observations["rhad:route@0x40A792"]
        assert scaled_setcc_calls["indirect_transfer_present"] is False
        assert scaled_setcc_calls["semantic_target_eas"] == [0x40A794, 0x40AEE6]
        assert scaled_setcc_calls["delivery_target_eas"] == [0x40A794, 0x40AEE6]
        if scaled_setcc_calls["source_present"]:
            assert scaled_setcc_calls["target_eas"] == [0x40A794, 0x40AEE6]
        else:
            assert scaled_setcc_calls["source_topology_retired"] is True
            assert scaled_setcc_calls["target_eas"] == []
        assert scaled_setcc_calls["semantic_targets_survive"] is True
        assert scaled_setcc_calls["passed"] is True
        row18_calls = calls_observations["rhad:route@0x40A7AC"]
        assert row18_calls["source_present"] is False
        assert row18_calls["source_topology_reachable"] is False
        assert row18_calls["source_topology_retired"] is True
        assert row18_calls["indirect_transfer_present"] is False
        assert row18_calls["target_eas"] == []
        assert row18_calls["semantic_target_eas"] == [0x40A5F0, 0x40A7AE]
        assert row18_calls["delivery_target_eas"] == [0x40A5F0, 0x40A7AE]
        assert row18_calls["semantic_targets_survive"] is True
        assert row18_calls["passed"] is True
        row19_calls = calls_observations["route:rhad-direct@0x40A7EF"]
        assert row19_calls["source_present"] is True
        assert row19_calls["source_topology_reachable"] is True
        assert row19_calls["source_topology_retired"] is False
        assert row19_calls["indirect_transfer_present"] is False
        assert row19_calls["target_eas"] == [0x40B6C0]
        assert row19_calls["boundary_exit_eas"] == [0x40B790]
        assert row19_calls["passed"] is True
        row20_calls = calls_observations["rhad:route@0x40A818"]
        assert row20_calls["source_present"] is False
        assert row20_calls["source_topology_reachable"] is False
        assert row20_calls["source_topology_retired"] is True
        assert row20_calls["indirect_transfer_present"] is False
        assert row20_calls["target_eas"] == []
        assert row20_calls["semantic_target_eas"] == [0x40A81A, 0x40AA60]
        assert row20_calls["delivery_target_eas"] == [0x40A81A, 0x40AA60]
        assert row20_calls["semantic_targets_survive"] is True
        assert row20_calls["passed"] is True
        row21_calls = calls_observations["rhad:route@0x40A832"]
        assert row21_calls["source_present"] is False
        assert row21_calls["source_topology_reachable"] is False
        assert row21_calls["source_topology_retired"] is True
        assert row21_calls["indirect_transfer_present"] is False
        assert row21_calls["target_eas"] == []
        assert row21_calls["semantic_target_eas"] == [0x40A834, 0x40AC3D]
        assert row21_calls["delivery_target_eas"] == [0x40A834, 0x40AC3D]
        assert row21_calls["semantic_targets_survive"] is True
        assert row21_calls["passed"] is True
        row22_calls = calls_observations["rhad:route@0x40A84C"]
        assert row22_calls["source_present"] is False
        assert row22_calls["source_topology_reachable"] is False
        assert row22_calls["source_topology_retired"] is True
        assert row22_calls["indirect_transfer_present"] is False
        assert row22_calls["target_eas"] == []
        assert row22_calls["semantic_target_eas"] == [0x40A84E, 0x40AFDF]
        assert row22_calls["delivery_target_eas"] == [0x40A84E, 0x40AFDF]
        assert row22_calls["semantic_targets_survive"] is True
        assert row22_calls["passed"] is True
        row23_calls = calls_observations["rhad:route@0x40A866"]
        assert row23_calls["source_present"] is False
        assert row23_calls["source_topology_reachable"] is False
        assert row23_calls["source_topology_retired"] is True
        assert row23_calls["indirect_transfer_present"] is False
        assert row23_calls["target_eas"] == []
        assert row23_calls["semantic_target_eas"] == [0x40A5F0, 0x40A868]
        assert row23_calls["delivery_target_eas"] == [0x40A5F0, 0x40A868]
        assert row23_calls["semantic_targets_survive"] is True
        assert row23_calls["passed"] is True
        row25_calls = calls_observations["route:rhad-direct@0x40A8B3"]
        assert row25_calls["source_present"] is False
        assert row25_calls["source_topology_reachable"] is False
        assert row25_calls["source_topology_retired"] is True
        assert row25_calls["indirect_transfer_present"] is False
        assert row25_calls["target_eas"] == []
        assert row25_calls["boundary_exit_eas"] == [0x40A663, 0x40AAFD]
        assert row25_calls["passed"] is True
        row26_calls = calls_observations["rhad:route@0x40A8CD"]
        assert row26_calls["source_present"] is False
        assert row26_calls["source_topology_reachable"] is False
        assert row26_calls["source_topology_retired"] is True
        assert row26_calls["indirect_transfer_present"] is False
        assert row26_calls["target_eas"] == []
        assert row26_calls["semantic_target_eas"] == [0x40A8CF, 0x40ACBF]
        assert row26_calls["delivery_target_eas"] == [0x40A8CF, 0x40ACBF]
        assert row26_calls["semantic_targets_survive"] is True
        assert row26_calls["passed"] is True
        row27_calls = calls_observations["rhad:route@0x40A8E7"]
        assert row27_calls["source_present"] is False
        assert row27_calls["source_topology_reachable"] is False
        assert row27_calls["source_topology_retired"] is True
        assert row27_calls["indirect_transfer_present"] is False
        assert row27_calls["target_eas"] == []
        assert row27_calls["semantic_target_eas"] == [0x40A8E9, 0x40B024]
        assert row27_calls["delivery_target_eas"] == [0x40A8E9, 0x40B024]
        assert row27_calls["semantic_targets_survive"] is True
        assert row27_calls["passed"] is True
        row28_calls = calls_observations["rhad:route@0x40A901"]
        assert row28_calls["source_present"] is False
        assert row28_calls["source_topology_reachable"] is False
        assert row28_calls["source_topology_retired"] is True
        assert row28_calls["indirect_transfer_present"] is False
        assert row28_calls["target_eas"] == []
        assert row28_calls["semantic_target_eas"] == [0x40A5F0, 0x40A903]
        assert row28_calls["delivery_target_eas"] == [0x40A5F0, 0x40A903]
        assert row28_calls["semantic_targets_survive"] is True
        assert row28_calls["passed"] is True
        row29_calls = calls_observations["route:rhad-direct@0x40A95E"]
        assert row29_calls["source_present"] is True
        assert row29_calls["source_topology_reachable"] is True
        assert row29_calls["source_topology_retired"] is False
        assert row29_calls["indirect_transfer_present"] is False
        assert row29_calls["target_eas"] == [0x40B6C0]
        assert row29_calls["boundary_exit_eas"] == [0x40B790]
        assert row29_calls["passed"] is True
        row30_calls = calls_observations["rhad:route@0x40A978"]
        assert row30_calls["source_present"] is False
        assert row30_calls["source_topology_reachable"] is False
        assert row30_calls["source_topology_retired"] is True
        assert row30_calls["indirect_transfer_present"] is False
        assert row30_calls["target_eas"] == []
        assert row30_calls["semantic_target_eas"] == [0x40A97A, 0x40AD1E]
        assert row30_calls["delivery_target_eas"] == [0x40A97A, 0x40AD1E]
        assert row30_calls["semantic_targets_survive"] is True
        assert row30_calls["passed"] is True
        row31_calls = calls_observations["rhad:route@0x40A992"]
        assert row31_calls["source_present"] is False
        assert row31_calls["source_topology_reachable"] is False
        assert row31_calls["source_topology_retired"] is True
        assert row31_calls["indirect_transfer_present"] is False
        assert row31_calls["target_eas"] == []
        assert row31_calls["semantic_target_eas"] == [0x40A994, 0x40B071]
        assert row31_calls["delivery_target_eas"] == [0x40A994, 0x40B071]
        assert row31_calls["semantic_targets_survive"] is True
        assert row31_calls["passed"] is True
        row32_calls = calls_observations["rhad:route@0x40A9AC"]
        assert row32_calls["source_present"] is False
        assert row32_calls["source_topology_reachable"] is False
        assert row32_calls["source_topology_retired"] is True
        assert row32_calls["indirect_transfer_present"] is False
        assert row32_calls["target_eas"] == []
        assert row32_calls["semantic_target_eas"] == [0x40A5F0, 0x40A9AE]
        assert row32_calls["delivery_target_eas"] == [0x40A5F0, 0x40A9AE]
        assert row32_calls["semantic_targets_survive"] is True
        assert row32_calls["passed"] is True
        row33_calls = calls_observations["rhad:route@0x40A9DC"]
        assert row33_calls["source_present"] is False
        assert row33_calls["source_topology_reachable"] is False
        assert row33_calls["source_topology_retired"] is True
        assert row33_calls["indirect_transfer_present"] is False
        assert row33_calls["target_eas"] == []
        assert row33_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row33_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row33_calls["semantic_targets_survive"] is True
        assert row33_calls["passed"] is True
        row34_calls = calls_observations["rhad:route@0x40A9F6"]
        assert row34_calls["source_present"] is False
        assert row34_calls["source_topology_reachable"] is False
        assert row34_calls["source_topology_retired"] is True
        assert row34_calls["indirect_transfer_present"] is False
        assert row34_calls["target_eas"] == []
        assert row34_calls["semantic_target_eas"] == [0x40A9F8, 0x40AD6E]
        assert row34_calls["delivery_target_eas"] == [0x40A9F8, 0x40AD6E]
        assert row34_calls["semantic_targets_survive"] is True
        assert row34_calls["passed"] is True
        row35_calls = calls_observations["rhad:route@0x40AA10"]
        assert row35_calls["source_present"] is False
        assert row35_calls["source_topology_reachable"] is False
        assert row35_calls["source_topology_retired"] is True
        assert row35_calls["indirect_transfer_present"] is False
        assert row35_calls["target_eas"] == []
        assert row35_calls["semantic_target_eas"] == [0x40AA12, 0x40B0BC]
        assert row35_calls["delivery_target_eas"] == [0x40AA12, 0x40B0BC]
        assert row35_calls["semantic_targets_survive"] is True
        assert row35_calls["passed"] is True
        row36_calls = calls_observations["rhad:route@0x40AA2A"]
        assert row36_calls["source_present"] is False
        assert row36_calls["source_topology_reachable"] is False
        assert row36_calls["source_topology_retired"] is True
        assert row36_calls["indirect_transfer_present"] is False
        assert row36_calls["target_eas"] == []
        assert row36_calls["semantic_target_eas"] == [0x40A5F0, 0x40AA2C]
        assert row36_calls["delivery_target_eas"] == [0x40A5F0, 0x40AA2C]
        assert row36_calls["semantic_targets_survive"] is True
        assert row36_calls["passed"] is True
        row37_calls = calls_observations["rhad:route@0x40AA5E"]
        assert row37_calls["source_present"] is False
        assert row37_calls["source_topology_reachable"] is False
        assert row37_calls["source_topology_retired"] is True
        assert row37_calls["indirect_transfer_present"] is False
        assert row37_calls["target_eas"] == []
        assert row37_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row37_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row37_calls["semantic_targets_survive"] is True
        assert row37_calls["passed"] is True
        row38_calls = calls_observations["rhad:route@0x40AA78"]
        assert row38_calls["source_present"] is False
        assert row38_calls["source_topology_reachable"] is False
        assert row38_calls["source_topology_retired"] is True
        assert row38_calls["indirect_transfer_present"] is False
        assert row38_calls["target_eas"] == []
        assert row38_calls["semantic_target_eas"] == [0x40AA7A, 0x40ADBE]
        assert row38_calls["delivery_target_eas"] == [0x40AA7A, 0x40ADBE]
        assert row38_calls["semantic_targets_survive"] is True
        assert row38_calls["passed"] is True
        row39_calls = calls_observations["rhad:route@0x40AA92"]
        assert row39_calls["source_present"] is False
        assert row39_calls["source_topology_reachable"] is False
        assert row39_calls["source_topology_retired"] is True
        assert row39_calls["indirect_transfer_present"] is False
        assert row39_calls["target_eas"] == []
        assert row39_calls["semantic_target_eas"] == [0x40AA94, 0x40B0F2]
        assert row39_calls["delivery_target_eas"] == [0x40AA94, 0x40B0F2]
        assert row39_calls["semantic_targets_survive"] is True
        assert row39_calls["passed"] is True
        row40_calls = calls_observations["rhad:route@0x40AAAC"]
        assert row40_calls["source_present"] is False
        assert row40_calls["source_topology_reachable"] is False
        assert row40_calls["source_topology_retired"] is True
        assert row40_calls["indirect_transfer_present"] is False
        assert row40_calls["target_eas"] == []
        assert row40_calls["semantic_target_eas"] == [0x40A5F0, 0x40AAAE]
        assert row40_calls["delivery_target_eas"] == [0x40A5F0, 0x40AAAE]
        assert row40_calls["semantic_targets_survive"] is True
        assert row40_calls["passed"] is True
        row42_calls = calls_observations["route:rhad-direct@0x40AAFB"]
        assert row42_calls["source_present"] is False
        assert row42_calls["source_topology_reachable"] is False
        assert row42_calls["source_topology_retired"] is True
        assert row42_calls["indirect_transfer_present"] is False
        assert row42_calls["target_eas"] == []
        assert row42_calls["boundary_exit_eas"] == [0x40AB17, 0x40B149]
        assert row42_calls["passed"] is True
        row43_calls = calls_observations["rhad:route@0x40AB15"]
        assert row43_calls["source_present"] is False
        assert row43_calls["source_topology_reachable"] is False
        assert row43_calls["source_topology_retired"] is True
        assert row43_calls["indirect_transfer_present"] is False
        assert row43_calls["target_eas"] == []
        assert row43_calls["semantic_target_eas"] == [0x40AB17, 0x40B149]
        assert row43_calls["delivery_target_eas"] == [0x40AB17, 0x40B149]
        assert row43_calls["semantic_targets_survive"] is True
        assert row43_calls["passed"] is True
        row44_calls = calls_observations["rhad:route@0x40AB2F"]
        assert row44_calls["source_present"] is False
        assert row44_calls["source_topology_reachable"] is False
        assert row44_calls["source_topology_retired"] is True
        assert row44_calls["indirect_transfer_present"] is False
        assert row44_calls["target_eas"] == []
        assert row44_calls["semantic_target_eas"] == [0x40A5F0, 0x40AB31]
        assert row44_calls["delivery_target_eas"] == [0x40A5F0, 0x40AB31]
        assert row44_calls["semantic_targets_survive"] is True
        assert row44_calls["passed"] is True
        row46_calls = calls_observations["rhad:route@0x40AB8E"]
        assert row46_calls["source_present"] is False
        assert row46_calls["source_topology_reachable"] is False
        assert row46_calls["source_topology_retired"] is True
        assert row46_calls["indirect_transfer_present"] is False
        assert row46_calls["target_eas"] == []
        assert row46_calls["semantic_target_eas"] == [0x40AB90, 0x40B17F]
        assert row46_calls["delivery_target_eas"] == [0x40AB90, 0x40B17F]
        assert row46_calls["semantic_targets_survive"] is True
        assert row46_calls["passed"] is True
        row47_calls = calls_observations["rhad:route@0x40ABA8"]
        assert row47_calls["source_present"] is False
        assert row47_calls["source_topology_reachable"] is False
        assert row47_calls["source_topology_retired"] is True
        assert row47_calls["indirect_transfer_present"] is False
        assert row47_calls["target_eas"] == []
        assert row47_calls["semantic_target_eas"] == [0x40A5F0, 0x40ABAA]
        assert row47_calls["delivery_target_eas"] == [0x40A5F0, 0x40ABAA]
        assert row47_calls["semantic_targets_survive"] is True
        assert row47_calls["passed"] is True
        row49_calls = calls_observations["rhad:route@0x40ABDE"]
        assert row49_calls["source_present"] is False
        assert row49_calls["source_topology_reachable"] is False
        assert row49_calls["source_topology_retired"] is True
        assert row49_calls["indirect_transfer_present"] is False
        assert row49_calls["target_eas"] == []
        assert row49_calls["semantic_target_eas"] == [0x40ABE0, 0x40B1D0]
        assert row49_calls["delivery_target_eas"] == [0x40ABE0, 0x40B1D0]
        assert row49_calls["semantic_targets_survive"] is True
        assert row49_calls["passed"] is True
        row50_calls = calls_observations["rhad:route@0x40ABF8"]
        assert row50_calls["source_present"] is False
        assert row50_calls["source_topology_reachable"] is False
        assert row50_calls["source_topology_retired"] is True
        assert row50_calls["indirect_transfer_present"] is False
        assert row50_calls["target_eas"] == []
        assert row50_calls["semantic_target_eas"] == [0x40A5F0, 0x40ABFA]
        assert row50_calls["delivery_target_eas"] == [0x40A5F0, 0x40ABFA]
        assert row50_calls["semantic_targets_survive"] is True
        assert row50_calls["passed"] is True
        row51_calls = calls_observations["route:rhad-direct@0x40AC3B"]
        assert row51_calls["source_present"] is True
        assert row51_calls["source_topology_reachable"] is False
        assert row51_calls["source_topology_retired"] is True
        assert row51_calls["indirect_transfer_present"] is False
        assert row51_calls["target_eas"] == [0x40B6C0]
        assert row51_calls["boundary_exit_eas"] == [0x40B790]
        assert row51_calls["passed"] is True
        row52_calls = calls_observations["rhad:route@0x40AC54"]
        assert row52_calls["source_present"] is False
        assert row52_calls["source_topology_reachable"] is False
        assert row52_calls["source_topology_retired"] is True
        assert row52_calls["indirect_transfer_present"] is False
        assert row52_calls["target_eas"] == []
        assert row52_calls["semantic_target_eas"] == [0x40AC56, 0x40B21C]
        assert row52_calls["delivery_target_eas"] == [0x40AC56, 0x40B21C]
        assert row52_calls["semantic_targets_survive"] is True
        assert row52_calls["passed"] is True
        row53_calls = calls_observations["rhad:route@0x40AC6E"]
        assert row53_calls["source_present"] is False
        assert row53_calls["source_topology_reachable"] is False
        assert row53_calls["source_topology_retired"] is True
        assert row53_calls["indirect_transfer_present"] is False
        assert row53_calls["target_eas"] == []
        assert row53_calls["semantic_target_eas"] == [0x40A5F0, 0x40AC70]
        assert row53_calls["delivery_target_eas"] == [0x40A5F0, 0x40AC70]
        assert row53_calls["semantic_targets_survive"] is True
        assert row53_calls["passed"] is True
        row54_calls = calls_observations["route:rhad-direct@0x40ACBD"]
        assert row54_calls["source_present"] is True
        assert row54_calls["source_topology_reachable"] is True
        assert row54_calls["source_topology_retired"] is False
        assert row54_calls["indirect_transfer_present"] is False
        assert row54_calls["target_eas"] == [0x40B6C0]
        assert row54_calls["boundary_exit_eas"] == [0x40B790]
        assert row54_calls["passed"] is True
        row55_calls = calls_observations["rhad:route@0x40ACD7"]
        assert row55_calls["source_present"] is False
        assert row55_calls["source_topology_reachable"] is False
        assert row55_calls["source_topology_retired"] is True
        assert row55_calls["indirect_transfer_present"] is False
        assert row55_calls["target_eas"] == []
        assert row55_calls["semantic_target_eas"] == [0x40ACD9, 0x40B26D]
        assert row55_calls["delivery_target_eas"] == [0x40ACD9, 0x40B26D]
        assert row55_calls["semantic_targets_survive"] is True
        assert row55_calls["passed"] is True
        row56_calls = calls_observations["rhad:route@0x40ACF1"]
        assert row56_calls["source_present"] is False
        assert row56_calls["source_topology_reachable"] is False
        assert row56_calls["source_topology_retired"] is True
        assert row56_calls["indirect_transfer_present"] is False
        assert row56_calls["target_eas"] == []
        assert row56_calls["semantic_target_eas"] == [0x40A5F0, 0x40ACF3]
        assert row56_calls["delivery_target_eas"] == [0x40A5F0, 0x40ACF3]
        assert row56_calls["semantic_targets_survive"] is True
        assert row56_calls["passed"] is True
        row57_calls = calls_observations["route:rhad-direct@0x40AD1C"]
        assert row57_calls["source_present"] is True
        assert row57_calls["source_topology_reachable"] is False
        assert row57_calls["source_topology_retired"] is True
        assert row57_calls["indirect_transfer_present"] is False
        assert row57_calls["target_eas"] == [0x40B6C0]
        assert row57_calls["boundary_exit_eas"] == [0x40B790]
        assert row57_calls["passed"] is True
        row58_calls = calls_observations["rhad:route@0x40AD36"]
        assert row58_calls["source_present"] is False
        assert row58_calls["source_topology_reachable"] is False
        assert row58_calls["source_topology_retired"] is True
        assert row58_calls["indirect_transfer_present"] is False
        assert row58_calls["target_eas"] == []
        assert row58_calls["semantic_target_eas"] == [0x40AD38, 0x40B2DB]
        assert row58_calls["delivery_target_eas"] == [0x40AD38, 0x40B2DB]
        assert row58_calls["semantic_targets_survive"] is True
        assert row58_calls["passed"] is True
        row59_calls = calls_observations["rhad:route@0x40AD50"]
        assert row59_calls["source_present"] is False
        assert row59_calls["source_topology_reachable"] is False
        assert row59_calls["source_topology_retired"] is True
        assert row59_calls["indirect_transfer_present"] is False
        assert row59_calls["target_eas"] == []
        assert row59_calls["semantic_target_eas"] == [0x40A5F0, 0x40AD52]
        assert row59_calls["delivery_target_eas"] == [0x40A5F0, 0x40AD52]
        assert row59_calls["semantic_targets_survive"] is True
        assert row59_calls["passed"] is True
        row60_calls = calls_observations["rhad:route@0x40AD6C"]
        assert row60_calls["source_present"] is False
        assert row60_calls["source_topology_reachable"] is False
        assert row60_calls["source_topology_retired"] is True
        assert row60_calls["indirect_transfer_present"] is False
        assert row60_calls["target_eas"] == []
        assert row60_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row60_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row60_calls["semantic_targets_survive"] is True
        assert row60_calls["passed"] is True
        row61_calls = calls_observations["rhad:route@0x40AD86"]
        assert row61_calls["source_present"] is False
        assert row61_calls["source_topology_reachable"] is False
        assert row61_calls["source_topology_retired"] is True
        assert row61_calls["indirect_transfer_present"] is False
        assert row61_calls["target_eas"] == []
        assert row61_calls["semantic_target_eas"] == [0x40AD88, 0x40B32C]
        assert row61_calls["delivery_target_eas"] == [0x40AD88, 0x40B32C]
        assert row61_calls["semantic_targets_survive"] is True
        assert row61_calls["passed"] is True
        row62_calls = calls_observations["rhad:route@0x40ADA0"]
        assert row62_calls["source_present"] is False
        assert row62_calls["source_topology_reachable"] is False
        assert row62_calls["source_topology_retired"] is True
        assert row62_calls["indirect_transfer_present"] is False
        assert row62_calls["target_eas"] == []
        assert row62_calls["semantic_target_eas"] == [0x40A5F0, 0x40ADA2]
        assert row62_calls["delivery_target_eas"] == [0x40A5F0, 0x40ADA2]
        assert row62_calls["semantic_targets_survive"] is True
        assert row62_calls["passed"] is True
        row63_calls = calls_observations["rhad:route@0x40ADBC"]
        assert row63_calls["source_present"] is False
        assert row63_calls["source_topology_reachable"] is False
        assert row63_calls["source_topology_retired"] is True
        assert row63_calls["indirect_transfer_present"] is False
        assert row63_calls["target_eas"] == []
        assert row63_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row63_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row63_calls["semantic_targets_survive"] is True
        assert row63_calls["passed"] is True
        row64_calls = calls_observations["rhad:route@0x40ADD6"]
        assert row64_calls["source_present"] is False
        assert row64_calls["source_topology_reachable"] is False
        assert row64_calls["source_topology_retired"] is True
        assert row64_calls["indirect_transfer_present"] is False
        assert row64_calls["target_eas"] == []
        assert row64_calls["semantic_target_eas"] == [0x40ADD8, 0x40B37C]
        assert row64_calls["delivery_target_eas"] == [0x40ADD8, 0x40B37C]
        assert row64_calls["semantic_targets_survive"] is True
        assert row64_calls["passed"] is True
        row65_calls = calls_observations["rhad:route@0x40ADF0"]
        assert row65_calls["source_present"] is False
        assert row65_calls["source_topology_reachable"] is False
        assert row65_calls["source_topology_retired"] is True
        assert row65_calls["indirect_transfer_present"] is False
        assert row65_calls["target_eas"] == []
        assert row65_calls["semantic_target_eas"] == [0x40A5F0, 0x40ADF2]
        assert row65_calls["delivery_target_eas"] == [0x40A5F0, 0x40ADF2]
        assert row65_calls["semantic_targets_survive"] is True
        assert row65_calls["passed"] is True
        row66_calls = calls_observations["rhad:route@0x40AE18"]
        assert row66_calls["source_present"] is False
        assert row66_calls["source_topology_reachable"] is False
        assert row66_calls["source_topology_retired"] is True
        assert row66_calls["indirect_transfer_present"] is False
        assert row66_calls["target_eas"] == []
        assert row66_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row66_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row66_calls["semantic_targets_survive"] is True
        assert row66_calls["passed"] is True
        row67_calls = calls_observations["route:rhad-direct@0x40AE24"]
        assert row67_calls["source_present"] is False
        assert row67_calls["source_topology_reachable"] is False
        assert row67_calls["source_topology_retired"] is True
        assert row67_calls["indirect_transfer_present"] is False
        assert row67_calls["target_eas"] == []
        assert row67_calls["boundary_exit_eas"] == [0x40A5F0, 0x40C898]
        assert row67_calls["passed"] is True
        row68_calls = calls_observations["rhad:route@0x40AE3C"]
        # Hex-Rays coalesces the native source EA before CALLS, but the
        # semantic observer still recognizes the live two-arm predicate
        # topology.  Do not misreport that live topology as retired.
        assert row68_calls["source_present"] is True
        assert row68_calls["source_topology_reachable"] is True
        assert row68_calls["source_topology_retired"] is False
        assert row68_calls["indirect_transfer_present"] is False
        assert row68_calls["target_eas"] == [0x40A5F0, 0x40AE3E]
        assert row68_calls["semantic_target_eas"] == [0x40A5F0, 0x40AE3E]
        assert row68_calls["delivery_target_eas"] == [0x40A5F0, 0x40AE3E]
        assert row68_calls["semantic_targets_survive"] is True
        assert row68_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row68_calls["passed"] is True
        row69_calls = calls_observations["rhad:route@0x40AE89"]
        assert row69_calls["source_present"] is False
        assert row69_calls["source_topology_reachable"] is False
        assert row69_calls["source_topology_retired"] is True
        assert row69_calls["indirect_transfer_present"] is False
        assert row69_calls["target_eas"] == []
        assert row69_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row69_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row69_calls["semantic_targets_survive"] is True
        assert row69_calls["boundary_exit_eas"] == [0x40A61B, 0x40A68C, 0x40B790]
        assert row69_calls["passed"] is True
        row70_calls = calls_observations["rhad:route@0x40AEA3"]
        assert row70_calls["source_present"] is False
        assert row70_calls["source_topology_reachable"] is False
        assert row70_calls["source_topology_retired"] is True
        assert row70_calls["indirect_transfer_present"] is False
        assert row70_calls["target_eas"] == []
        assert row70_calls["semantic_target_eas"] == [0x40A5F0, 0x40AEA5]
        assert row70_calls["delivery_target_eas"] == [0x40A5F0, 0x40AEA5]
        assert row70_calls["semantic_targets_survive"] is True
        assert row70_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row70_calls["passed"] is True
        row71_calls = calls_observations["route:rhad-direct@0x40AEE4"]
        assert row71_calls["source_present"] is True
        assert row71_calls["source_topology_reachable"] is True
        assert row71_calls["source_topology_retired"] is False
        assert row71_calls["indirect_transfer_present"] is False
        assert row71_calls["target_eas"] == [0x40B6C0]
        assert row71_calls["boundary_exit_eas"] == [0x40B790]
        assert row71_calls["passed"] is True
        row72_calls = calls_observations["rhad:route@0x40AEFE"]
        assert row72_calls["source_present"] is False
        assert row72_calls["source_topology_reachable"] is False
        assert row72_calls["source_topology_retired"] is True
        assert row72_calls["indirect_transfer_present"] is False
        assert row72_calls["target_eas"] == []
        assert row72_calls["semantic_target_eas"] == [0x40A5F0, 0x40AF00]
        assert row72_calls["delivery_target_eas"] == [0x40A5F0, 0x40AF00]
        assert row72_calls["semantic_targets_survive"] is True
        assert row72_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row72_calls["passed"] is True
        row73_calls = calls_observations["route:rhad-direct@0x40AFDD"]
        assert row73_calls["source_present"] is True
        assert row73_calls["source_topology_reachable"] is True
        assert row73_calls["source_topology_retired"] is False
        assert row73_calls["indirect_transfer_present"] is False
        assert row73_calls["target_eas"] == [0x40B6C0]
        assert row73_calls["boundary_exit_eas"] == [0x40B790]
        assert row73_calls["passed"] is True
        row74_calls = calls_observations["rhad:route@0x40AFF7"]
        assert row74_calls["source_present"] is False
        assert row74_calls["source_topology_reachable"] is False
        assert row74_calls["source_topology_retired"] is True
        assert row74_calls["indirect_transfer_present"] is False
        assert row74_calls["target_eas"] == []
        assert row74_calls["semantic_target_eas"] == [0x40A5F0, 0x40AFF9]
        assert row74_calls["delivery_target_eas"] == [0x40A5F0, 0x40AFF9]
        assert row74_calls["semantic_targets_survive"] is True
        assert row74_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row74_calls["passed"] is True
        row75_calls = calls_observations["route:rhad-direct@0x40B022"]
        assert row75_calls["source_present"] is True
        assert row75_calls["source_topology_reachable"] is True
        assert row75_calls["source_topology_retired"] is False
        assert row75_calls["indirect_transfer_present"] is False
        assert row75_calls["target_eas"] == [0x40B6C0]
        assert row75_calls["boundary_exit_eas"] == [0x40B790]
        assert row75_calls["passed"] is True
        row76_calls = calls_observations["rhad:route@0x40B03C"]
        assert row76_calls["source_present"] is False
        assert row76_calls["source_topology_reachable"] is False
        assert row76_calls["source_topology_retired"] is True
        assert row76_calls["indirect_transfer_present"] is False
        assert row76_calls["target_eas"] == []
        assert row76_calls["semantic_target_eas"] == [0x40A5F0, 0x40B03E]
        assert row76_calls["delivery_target_eas"] == [0x40A5F0, 0x40B03E]
        assert row76_calls["semantic_targets_survive"] is True
        assert row76_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row76_calls["passed"] is True
        row77_calls = calls_observations["route:rhad-direct@0x40B06F"]
        assert row77_calls["source_present"] is True
        assert row77_calls["source_topology_reachable"] is True
        assert row77_calls["source_topology_retired"] is False
        assert row77_calls["indirect_transfer_present"] is False
        assert row77_calls["target_eas"] == [0x40B6C0]
        assert row77_calls["boundary_exit_eas"] == [0x40B790]
        assert row77_calls["passed"] is True
        row78_calls = calls_observations["rhad:route@0x40B089"]
        assert row78_calls["source_present"] is False
        assert row78_calls["source_topology_reachable"] is False
        assert row78_calls["source_topology_retired"] is True
        assert row78_calls["indirect_transfer_present"] is False
        assert row78_calls["target_eas"] == []
        assert row78_calls["semantic_target_eas"] == [0x40A5F0, 0x40B08B]
        assert row78_calls["delivery_target_eas"] == [0x40A5F0, 0x40B08B]
        assert row78_calls["semantic_targets_survive"] is True
        assert row78_calls["boundary_exit_eas"] == [0x40A607, 0x40B6C0]
        assert row78_calls["passed"] is True
        row79_calls = calls_observations["rhad:route@0x40B0BA"]
        assert row79_calls["source_present"] is False
        assert row79_calls["source_topology_reachable"] is False
        assert row79_calls["source_topology_retired"] is True
        assert row79_calls["indirect_transfer_present"] is False
        assert row79_calls["target_eas"] == []
        assert row79_calls["semantic_target_eas"] == [0x40A607, 0x40B6C0]
        assert row79_calls["delivery_target_eas"] == [0x40A607, 0x40B6C0]
        assert row79_calls["semantic_targets_survive"] is True
        assert row79_calls["boundary_exit_eas"] == [
            0x40A61B,
            0x40A68C,
            0x40B790,
        ]
        assert row79_calls["passed"] is True
        assert 0x40B6C0 in calls_payload["reachable_eas"]
        assert connection.execute(
            "SELECT COUNT(*) FROM lifecycle_events "
            "WHERE event_kind='ctree_captured' AND maturity='CMAT_FINAL'"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT planned_operation_count, applied_operation_count, outcome "
            "FROM mutation_receipts"
        ).fetchall() == [(560, 560, "committed")]
        assert connection.execute(
            "SELECT current_phase, mutation_started, poisoned, interr_code "
            "FROM cfg_transaction_attempts"
        ).fetchall() == [("committed", 1, 0, None)]
        assert connection.execute(
            "SELECT outcome, fragment_staged, root_publication_attempted, "
            "root_publication_succeeded, rollback_attempted "
            "FROM semantic_fragment_transactions"
        ).fetchall() == [("committed", 1, 1, 1, 0)]
        assert connection.execute(
            "SELECT COUNT(*) FROM semantic_fragment_route_oracle_comparisons "
            "WHERE outcome='matched'"
        ).fetchone() == (75,)
        committed_witnesses = connection.execute(
            "SELECT local_block_id, provenance, logical_proxy_token, "
            "logical_version, logical_generation, insertion_quantity_before, "
            "insertion_quantity_after, requested_insertion_serial, "
            "returned_serial, invalidated "
            "FROM cfg_creation_witnesses WHERE state='committed' "
            "ORDER BY rowid"
        ).fetchall()
        imported_witnesses = tuple(
            row for row in committed_witnesses if row[1] == "imported_native"
        )
        assert tuple(row[0] for row in imported_witnesses) == _IMPORTED_BLOCK_IDS
        assert all(
            row[1] == "imported_native"
            and row[2]
            and row[3:5] == (0, 1)
            and row[6] == row[5] + 1
            and row[7] == row[8]
            and row[9] == 0
            for row in imported_witnesses
        )
        helper_witnesses = tuple(
            row for row in committed_witnesses if row[1] == "created_synthetic"
        )
        assert len(helper_witnesses) == 1
        helper_witness = helper_witnesses[0]
        assert helper_witness[0] == "fallthrough-helper:rhad:route@0x40AE3C"
        assert helper_witness[2]
        assert helper_witness[3:5] == (0, 1)
        assert helper_witness[6] == helper_witness[5] + 1
        assert helper_witness[7] == helper_witness[8]
        assert helper_witness[9] == 0


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--worker":
        raise SystemExit(
            "usage: test_rhad_generated_checksum_publication.py --worker BINARY"
        )
    _run_worker(pathlib.Path(sys.argv[2]))
