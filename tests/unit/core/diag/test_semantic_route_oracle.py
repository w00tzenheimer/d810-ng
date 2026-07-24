from __future__ import annotations

import json

from d810.core.diag import create_diag_database
from d810.core.diag.semantic_route_oracle import (
    load_snapshot_blocks,
    record_route_oracle_capture,
    record_route_oracle_comparisons,
    record_route_oracle_run,
    record_route_reference_rewrite,
)
from d810.core.diag.snapshot import snapshot_mba
from d810.core.observability_models import BlockSnapshot, InstructionSnapshot
from d810.core.semantic_route_oracle import (
    ReferenceRouteRewrite,
    RouteCaptureLane,
    RouteOracleCapture,
    RouteOracleRun,
    SemanticTransferKind,
    compare_route_maturities,
    observe_route_shape,
)


_FUNCTION_EA = 0x40A560
_OWNER_EA = 0x40BB51
_REWRITE_ANCHOR_EA = 0x40BB63
_DIRECT_TARGET_EA = 0x40ACF3
_ORIGINAL_TAKEN_EA = 0x40C6F7
_ORIGINAL_FALLTHROUGH_EA = 0x40BB69


def _instruction(
    index: int,
    ea: int,
    opcode_name: str,
    *,
    target_serial: int | None = None,
) -> InstructionSnapshot:
    operand_slot = "l" if opcode_name == "m_goto" else "d"
    meta = {
        "opcode": 0,
        "opcode_name": opcode_name,
        "ea": f"0x{ea:x}",
    }
    if target_serial is not None:
        meta[operand_slot] = {
            "type": "mop_b",
            "type_num": 0,
            "size": 0,
            "dstr": f"@{target_serial}",
            "block_num": target_serial,
        }
    return InstructionSnapshot(
        index=index,
        ea=ea,
        opcode=0,
        opcode_name=opcode_name,
        dstr=opcode_name,
        meta=json.dumps(meta, sort_keys=True),
    )


def _direct_blocks(*, owner_serial: int, target_serial: int) -> list[BlockSnapshot]:
    synthetic_entry_serial = owner_serial - 2
    native_entry_serial = owner_serial - 1
    return [
        BlockSnapshot(
            serial=synthetic_entry_serial,
            block_type=3,
            type_name="BLT_1WAY",
            start_ea=_FUNCTION_EA,
            end_ea=_FUNCTION_EA,
            nsucc=1,
            succs=[native_entry_serial],
        ),
        BlockSnapshot(
            serial=native_entry_serial,
            block_type=3,
            type_name="BLT_1WAY",
            start_ea=_FUNCTION_EA,
            end_ea=_FUNCTION_EA + 1,
            nsucc=1,
            npred=1,
            succs=[owner_serial],
            preds=[synthetic_entry_serial],
            instructions=[
                _instruction(0, _FUNCTION_EA, "m_goto", target_serial=owner_serial)
            ],
        ),
        BlockSnapshot(
            serial=owner_serial,
            block_type=3,
            type_name="BLT_1WAY",
            start_ea=_OWNER_EA,
            end_ea=_REWRITE_ANCHOR_EA + 5,
            nsucc=1,
            npred=1,
            succs=[target_serial],
            preds=[native_entry_serial],
            instructions=[
                _instruction(
                    0,
                    _REWRITE_ANCHOR_EA,
                    "m_mov",
                ),
                _instruction(
                    1,
                    _REWRITE_ANCHOR_EA,
                    "m_goto",
                    target_serial=target_serial,
                ),
            ],
        ),
        BlockSnapshot(
            serial=target_serial,
            block_type=2,
            type_name="BLT_0WAY",
            start_ea=_DIRECT_TARGET_EA,
            end_ea=_DIRECT_TARGET_EA + 1,
            npred=1,
            preds=[owner_serial],
        ),
    ]


def _conditional_blocks() -> list[BlockSnapshot]:
    return [
        BlockSnapshot(
            serial=4,
            block_type=3,
            type_name="BLT_1WAY",
            start_ea=_FUNCTION_EA,
            end_ea=_FUNCTION_EA + 1,
            nsucc=1,
            succs=[5],
            instructions=[_instruction(0, _FUNCTION_EA, "m_goto", target_serial=5)],
        ),
        BlockSnapshot(
            serial=5,
            block_type=4,
            type_name="BLT_2WAY",
            start_ea=_OWNER_EA,
            end_ea=_REWRITE_ANCHOR_EA + 6,
            nsucc=2,
            npred=1,
            succs=[6, 9],
            preds=[4],
            instructions=[
                _instruction(
                    0,
                    _REWRITE_ANCHOR_EA,
                    "m_jge",
                    target_serial=9,
                )
            ],
        ),
        BlockSnapshot(
            serial=6,
            block_type=2,
            type_name="BLT_0WAY",
            start_ea=_ORIGINAL_FALLTHROUGH_EA,
            end_ea=_ORIGINAL_FALLTHROUGH_EA + 1,
            npred=1,
            preds=[5],
        ),
        BlockSnapshot(
            serial=9,
            block_type=2,
            type_name="BLT_0WAY",
            start_ea=_ORIGINAL_TAKEN_EA,
            end_ea=_ORIGINAL_TAKEN_EA + 1,
            npred=1,
            preds=[5],
        ),
    ]


def _reference_rewrite() -> ReferenceRouteRewrite:
    return ReferenceRouteRewrite(
        route_id="rhad:0x40A560:flow_route:0x40BB63",
        function_ea=_FUNCTION_EA,
        owner_ea=_OWNER_EA,
        rewrite_anchor_ea=_REWRITE_ANCHOR_EA,
        corridor=((0x40BB44, 0x40BB69),),
        reference_phase="flow_route",
        original_transfer_kind=SemanticTransferKind.CONDITIONAL,
        final_transfer_kind=SemanticTransferKind.DIRECT,
        direct_target_ea=_DIRECT_TARGET_EA,
        reference_ledger_identity="flow_route:0x40BB63",
        reference_ledger_json=json.dumps(
            {
                "planned_branches": [
                    {
                        "anchor_ea": _REWRITE_ANCHOR_EA,
                        "opcode": "e9",
                        "target_ea": _DIRECT_TARGET_EA,
                    }
                ]
            },
            sort_keys=True,
        ),
    )


def test_direct_route_shape_is_serial_free_and_matches_reference_ledger() -> None:
    route = _reference_rewrite()

    low_serial = observe_route_shape(
        route,
        _direct_blocks(owner_serial=2, target_serial=3),
        lane=RouteCaptureLane.REFERENCE,
        maturity="MMAT_PREOPTIMIZED",
    )
    high_serial = observe_route_shape(
        route,
        _direct_blocks(owner_serial=77, target_serial=91),
        lane=RouteCaptureLane.REFERENCE,
        maturity="MMAT_PREOPTIMIZED",
    )

    assert low_serial.outcome == "observed"
    assert low_serial.shape == high_serial.shape
    assert low_serial.shape is not None
    assert low_serial.shape.transfer_kind is SemanticTransferKind.DIRECT
    assert low_serial.shape.terminator_opcode == "m_goto"
    assert low_serial.shape.direct_target_ea == _DIRECT_TARGET_EA
    assert low_serial.shape.successor_eas == (_DIRECT_TARGET_EA,)
    assert low_serial.shape.predicate_kind is None
    assert low_serial.shape.reachable_from_entry is True
    assert "serial" not in low_serial.shape.to_json()


def test_comparison_records_first_stable_route_divergence_by_maturity() -> None:
    route = _reference_rewrite()
    reference = {
        maturity: observe_route_shape(
            route,
            _direct_blocks(owner_serial=2, target_serial=3),
            lane=RouteCaptureLane.REFERENCE,
            maturity=maturity,
        )
        for maturity in ("MMAT_GENERATED", "MMAT_PREOPTIMIZED", "MMAT_CALLS")
    }
    candidate = {
        maturity: observe_route_shape(
            route,
            _conditional_blocks(),
            lane=RouteCaptureLane.CANDIDATE,
            maturity=maturity,
        )
        for maturity in ("MMAT_GENERATED", "MMAT_PREOPTIMIZED", "MMAT_CALLS")
    }

    comparisons = compare_route_maturities(
        route,
        reference,
        candidate,
        maturity_order=("MMAT_GENERATED", "MMAT_PREOPTIMIZED", "MMAT_CALLS"),
        candidate_variant="unpatched_baseline",
    )

    assert [comparison.outcome for comparison in comparisons] == [
        "diverged",
        "diverged",
        "diverged",
    ]
    assert comparisons[0].first_divergence is True
    assert comparisons[1].first_divergence is False
    assert comparisons[0].failed_invariant == "transfer_kind"
    assert comparisons[0].owner_ea == _OWNER_EA
    assert comparisons[0].rewrite_anchor_ea == _REWRITE_ANCHOR_EA
    assert comparisons[0].candidate_shape is not None
    assert comparisons[0].candidate_shape.true_target_ea == _ORIGINAL_TAKEN_EA
    assert comparisons[0].candidate_shape.false_target_ea == (_ORIGINAL_FALLTHROUGH_EA)
    assert comparisons[0].candidate_shape.physical_fallthrough_ea == (
        _ORIGINAL_FALLTHROUGH_EA
    )


def test_oracle_chain_is_persisted_with_snapshot_links_and_native_anchors() -> None:
    db = create_diag_database(":memory:")
    conn = db.connection()
    run = RouteOracleRun(
        run_id="a560-v33-fixture",
        function_ea=_FUNCTION_EA,
        fixture_sha256="24" * 32,
        reference_binary_sha256="63" * 32,
        candidate_binary_sha256="24" * 32,
        reference_commit="21b0d4783703bc4fb6910cfae51d92cd683d2c65",
        runtime_image="d810-idapro-9.3-test-runtime:py313-v1",
        runtime_image_id="sha256:360f91d9d4ac",
        cache_disabled=True,
    )
    route = _reference_rewrite()
    reference_snapshot = snapshot_mba(
        conn,
        _direct_blocks(owner_serial=2, target_serial=3),
        "reference_generated",
        _FUNCTION_EA,
        maturity="MMAT_GENERATED",
        phase="pre_d810",
    )
    candidate_snapshot = snapshot_mba(
        conn,
        _conditional_blocks(),
        "candidate_generated",
        _FUNCTION_EA,
        maturity="MMAT_GENERATED",
        phase="pre_d810",
    )
    comparison = compare_route_maturities(
        route,
        {
            "MMAT_GENERATED": observe_route_shape(
                route,
                load_snapshot_blocks(conn, reference_snapshot),
                lane=RouteCaptureLane.REFERENCE,
                maturity="MMAT_GENERATED",
            )
        },
        {
            "MMAT_GENERATED": observe_route_shape(
                route,
                load_snapshot_blocks(conn, candidate_snapshot),
                lane=RouteCaptureLane.CANDIDATE,
                maturity="MMAT_GENERATED",
            )
        },
        maturity_order=("MMAT_GENERATED",),
        candidate_variant="unpatched_baseline",
    )

    record_route_oracle_run(conn, run)
    record_route_reference_rewrite(conn, run.run_id, route)
    record_route_oracle_capture(
        conn,
        RouteOracleCapture(
            run_id=run.run_id,
            lane=RouteCaptureLane.REFERENCE,
            candidate_variant="reference_patched",
            maturity="MMAT_GENERATED",
            snapshot_id=reference_snapshot,
            binary_sha256=run.reference_binary_sha256,
            d810_enabled=False,
            cache_disabled=True,
        ),
    )
    record_route_oracle_capture(
        conn,
        RouteOracleCapture(
            run_id=run.run_id,
            lane=RouteCaptureLane.CANDIDATE,
            candidate_variant="unpatched_baseline",
            maturity="MMAT_GENERATED",
            snapshot_id=candidate_snapshot,
            binary_sha256=run.candidate_binary_sha256,
            d810_enabled=False,
            cache_disabled=True,
        ),
    )
    record_route_oracle_comparisons(
        conn,
        run_id=run.run_id,
        reference_snapshot_ids={"MMAT_GENERATED": reference_snapshot},
        candidate_snapshot_ids={"MMAT_GENERATED": candidate_snapshot},
        comparisons=comparison,
    )

    persisted = conn.execute(
        "SELECT maturity, outcome, first_divergence, failed_invariant, "
        "owner_ea_hex, rewrite_anchor_ea_hex, reference_snapshot_id, "
        "candidate_snapshot_id, oracle_shape_json, candidate_shape_json "
        "FROM semantic_route_oracle_comparisons"
    ).fetchone()
    assert persisted[:8] == (
        "MMAT_GENERATED",
        "diverged",
        1,
        "transfer_kind",
        "0x000000000040bb51",
        "0x000000000040bb63",
        reference_snapshot,
        candidate_snapshot,
    )
    assert "serial" not in persisted[8]
    assert "serial" not in persisted[9]

    capture_rows = conn.execute(
        "SELECT lane, candidate_variant, snapshot_id FROM "
        "semantic_route_oracle_captures ORDER BY lane DESC"
    ).fetchall()
    assert capture_rows == [
        ("reference", "reference_patched", reference_snapshot),
        ("candidate", "unpatched_baseline", candidate_snapshot),
    ]
