from __future__ import annotations

import hashlib
import json

import pytest

from d810.core.semantic_route_oracle import SemanticTransferKind
from tools.scripts.rhad_investigation.semantic_route_oracle import (
    build_manifest,
    routes_from_manifest,
    run_from_manifest,
)


def _ledger() -> dict[str, object]:
    return {
        "binary_sha256": hashlib.sha256(b"candidate").hexdigest(),
        "reference": {"commit": "21b0d4783703bc4fb6910cfae51d92cd683d2c65"},
        "transactions": [
            {
                "corridor": [
                    {
                        "bytes": "bbef95970e",
                        "ea": 0x40BB44,
                        "mnemonic": "mov",
                        "op_str": "ebx, 0xe9795ef",
                        "size": 5,
                        "writes_flags": False,
                    },
                    {
                        "bytes": "0f8d8e0b0000",
                        "ea": 0x40BB63,
                        "mnemonic": "jge",
                        "op_str": "0x40c6f7",
                        "size": 6,
                        "writes_flags": False,
                    },
                ],
                "corridor_end_ea": 0x40BB69,
                "corridor_start_ea": 0x40BB44,
                "flag_writer_eas": [],
                "flow_register": "ebx",
                "function_ea": 0x40A560,
                "phase": "flow_route",
                "planned_branches": [
                    {
                        "anchor_ea": 0x40BB63,
                        "opcode": "e9",
                        "target_ea": 0x40ACF3,
                    }
                ],
                "state_writes": [
                    {
                        "ea": 0x40BB44,
                        "mnemonic": "mov",
                        "value": 0x0E9795EF,
                        "value_kind": "immediate",
                    }
                ],
                "status": "committed",
            }
        ],
    }


def _conditional_ledger() -> dict[str, object]:
    ledger = _ledger()
    ledger["transactions"] = [
        {
            "corridor": [
                {
                    "bytes": "8b5c2440",
                    "ea": 0x40BECC,
                    "mnemonic": "mov",
                    "op_str": "ebx, dword ptr [esp + 0x40]",
                    "size": 4,
                    "writes_flags": False,
                },
                {
                    "bytes": "81fb65d3b20b",
                    "ea": 0x40BED0,
                    "mnemonic": "cmp",
                    "op_str": "ebx, 0xbb2d365",
                    "size": 6,
                    "writes_flags": True,
                },
                {
                    "bytes": "0f8ce4f7ffff",
                    "ea": 0x40BED6,
                    "mnemonic": "jl",
                    "op_str": "0x40b6c0",
                    "size": 6,
                    "writes_flags": False,
                },
                {
                    "bytes": "e926e7ffff",
                    "ea": 0x40BEDC,
                    "mnemonic": "jmp",
                    "op_str": "0x40a607",
                    "size": 5,
                    "writes_flags": False,
                },
            ],
            "corridor_end_ea": 0x40BEE1,
            "corridor_start_ea": 0x40BECC,
            "flag_writer_eas": [0x40BED0],
            "flow_register": "ebx",
            "function_ea": 0x40A560,
            "phase": "flow_route",
            "planned_branches": [
                {
                    "anchor_ea": 0x40BED0,
                    "opcode": "837d0c00",
                    "target_ea": None,
                },
                {
                    "anchor_ea": 0x40BED6,
                    "opcode": "0f84",
                    "target_ea": 0x40B9A6,
                },
                {
                    "anchor_ea": 0x40BEDC,
                    "opcode": "e9",
                    "target_ea": 0x40C26D,
                },
            ],
            "state_writes": [
                {
                    "ea": 0x40BECC,
                    "mnemonic": "mov",
                    "value": None,
                    "value_kind": "non_immediate",
                }
            ],
            "status": "committed",
        }
    ]
    return ledger


def test_manifest_is_derived_from_exact_reference_transaction(tmp_path) -> None:
    fixture = tmp_path / "fixture.bin"
    reference = tmp_path / "reference.bin"
    fixture.write_bytes(b"candidate")
    reference.write_bytes(b"reference")

    manifest = build_manifest(
        ledger=_ledger(),
        run_id="a560-v33-40bb63",
        function_ea=0x40A560,
        function_end_ea=0x40C8A2,
        publication_root_ea=0x40BB51,
        rewrite_owners={0x40BB63: 0x40BB51},
        fixture_path=fixture,
        reference_binary_path=reference,
        reference_commit="21b0d4783703bc4fb6910cfae51d92cd683d2c65",
        runtime_image="d810-idapro-9.3-test-runtime:py313-v1",
        runtime_image_id="sha256:360f91d9d4ac",
        maturities=(
            "MMAT_GENERATED",
            "MMAT_PREOPTIMIZED",
            "MMAT_CALLS",
            "MMAT_GLBOPT1",
        ),
    )

    route = routes_from_manifest(manifest)[0]
    assert route.route_id == "rhad:0x40A560:flow_route:0x40BB63"
    assert route.owner_ea == 0x40BB51
    assert route.rewrite_anchor_ea == 0x40BB63
    assert route.corridor == ((0x40BB44, 0x40BB69),)
    assert route.original_transfer_kind is SemanticTransferKind.CONDITIONAL
    assert route.final_transfer_kind is SemanticTransferKind.DIRECT
    assert route.direct_target_ea == 0x40ACF3
    assert route.reference_phase == "flow_route"
    assert json.loads(route.reference_ledger_json) == _ledger()["transactions"][0]

    run = run_from_manifest(manifest)
    assert run.run_id == "a560-v33-40bb63"
    assert run.fixture_sha256 == _ledger()["binary_sha256"]
    assert run.cache_disabled is True
    assert manifest["capture"] == {
        "function_end_ea": "0x40C8A2",
        "maturities": [
            "MMAT_GENERATED",
            "MMAT_PREOPTIMIZED",
            "MMAT_CALLS",
            "MMAT_GLBOPT1",
        ],
    }
    assert manifest["publication_root_ea"] == "0x40BB51"
    assert manifest["schema_version"] == 2


def test_manifest_rejects_missing_or_ambiguous_reference_anchor(tmp_path) -> None:
    fixture = tmp_path / "fixture.bin"
    reference = tmp_path / "reference.bin"
    fixture.write_bytes(b"candidate")
    reference.write_bytes(b"reference")
    kwargs = {
        "ledger": _ledger(),
        "run_id": "a560-v33-40bb63",
        "function_ea": 0x40A560,
        "function_end_ea": 0x40C8A2,
        "publication_root_ea": 0x40BB51,
        "fixture_path": fixture,
        "reference_binary_path": reference,
        "reference_commit": "21b0d4783703bc4fb6910cfae51d92cd683d2c65",
        "runtime_image": "d810-idapro-9.3-test-runtime:py313-v1",
        "runtime_image_id": "sha256:360f91d9d4ac",
        "maturities": ("MMAT_PREOPTIMIZED",),
    }

    with pytest.raises(ValueError, match="no committed reference transaction"):
        build_manifest(rewrite_owners={0x40BB64: 0x40BB51}, **kwargs)

    duplicated = _ledger()
    duplicated["transactions"] = [
        duplicated["transactions"][0],
        dict(duplicated["transactions"][0]),
    ]
    with pytest.raises(ValueError, match="2 committed reference transactions"):
        build_manifest(
            rewrite_owners={0x40BB63: 0x40BB51},
            **{**kwargs, "ledger": duplicated},
        )


def test_manifest_compiles_conditional_rewrite_with_predicate_setup(tmp_path) -> None:
    fixture = tmp_path / "fixture.bin"
    reference = tmp_path / "reference.bin"
    fixture.write_bytes(b"candidate")
    reference.write_bytes(b"reference")

    manifest = build_manifest(
        ledger=_conditional_ledger(),
        run_id="a560-v33-conditional",
        function_ea=0x40A560,
        function_end_ea=0x40C8A2,
        publication_root_ea=0x40BECC,
        rewrite_owners={0x40BED0: 0x40BECC},
        fixture_path=fixture,
        reference_binary_path=reference,
        reference_commit="21b0d4783703bc4fb6910cfae51d92cd683d2c65",
        runtime_image="d810-idapro-9.3-test-runtime:py313-v1",
        runtime_image_id="sha256:360f91d9d4ac",
        maturities=("MMAT_PREOPTIMIZED",),
    )

    (route,) = routes_from_manifest(manifest)
    assert route.route_id == "rhad:0x40A560:flow_route:0x40BED0"
    assert route.owner_ea == 0x40BECC
    assert route.rewrite_anchor_ea == 0x40BED0
    assert route.original_transfer_kind is SemanticTransferKind.UNKNOWN
    assert route.final_transfer_kind is SemanticTransferKind.CONDITIONAL
    assert route.predicate_kind == "z"
    assert route.true_target_ea == 0x40B9A6
    assert route.false_target_ea == 0x40C26D


def test_manifest_parser_rejects_unknown_schema() -> None:
    with pytest.raises(ValueError, match="schema version"):
        routes_from_manifest({"schema_version": 99})
