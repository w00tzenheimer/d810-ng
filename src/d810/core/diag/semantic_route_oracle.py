"""SQLite persistence for portable semantic-route oracle observations."""

from __future__ import annotations

import json
import sqlite3
import time

from d810.core.diag import active_diag_db, diag_models_on
from d810.core.diag.models import (
    SemanticRouteOracleCaptureRecord,
    SemanticRouteOracleComparisonRecord,
    SemanticRouteOracleRunRecord,
    SemanticRouteReferenceRewriteRecord,
)
from d810.core.diag.snapshot import _dual
from d810.core.observability_models import BlockSnapshot, InstructionSnapshot
from d810.core.semantic_route_oracle import (
    ReferenceRouteRewrite,
    RouteOracleCapture,
    RouteOracleComparison,
    RouteOracleRun,
)
from d810.core.typing import Mapping, Sequence


def _write_db():
    database = active_diag_db()
    if database is None:
        raise RuntimeError("semantic route oracle writer has no active diagnostic DB")
    return database


def _unsigned_from_dual(hex_value: str | None, i64_value: int | None) -> int | None:
    if hex_value is not None:
        return int(hex_value, 16)
    return None if i64_value is None else int(i64_value) & 0xFFFFFFFFFFFFFFFF


def record_route_oracle_run(
    conn: sqlite3.Connection,
    run: RouteOracleRun,
) -> None:
    """Persist the immutable environment identity for one two-lane run."""

    del conn
    func_hex, func_i64 = _dual(run.function_ea)
    database = _write_db()
    with diag_models_on(database), database.atomic():
        SemanticRouteOracleRunRecord.create(
            run_id=run.run_id,
            func_ea_hex=func_hex,
            func_ea_i64=func_i64,
            fixture_sha256=run.fixture_sha256.lower(),
            reference_binary_sha256=run.reference_binary_sha256.lower(),
            candidate_binary_sha256=run.candidate_binary_sha256.lower(),
            reference_commit=run.reference_commit,
            runtime_image=run.runtime_image,
            runtime_image_id=run.runtime_image_id,
            cache_disabled=int(run.cache_disabled),
            created_at=time.time(),
            metadata_json=json.dumps(
                json.loads(run.metadata_json),
                sort_keys=True,
                separators=(",", ":"),
            ),
        )


def record_route_reference_rewrite(
    conn: sqlite3.Connection,
    run_id: str,
    route: ReferenceRouteRewrite,
) -> None:
    """Persist one unchanged-reference rewrite and its stable native identity."""

    del conn
    func_hex, func_i64 = _dual(route.function_ea)
    owner_hex, owner_i64 = _dual(route.owner_ea)
    anchor_hex, anchor_i64 = _dual(route.rewrite_anchor_ea)
    direct_hex, direct_i64 = _dual(route.direct_target_ea)
    true_hex, true_i64 = _dual(route.true_target_ea)
    false_hex, false_i64 = _dual(route.false_target_ea)
    corridor_json = json.dumps(
        [
            {"end_ea": f"0x{end_ea:X}", "start_ea": f"0x{start_ea:X}"}
            for start_ea, end_ea in route.corridor
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    database = _write_db()
    with diag_models_on(database), database.atomic():
        SemanticRouteReferenceRewriteRecord.create(
            run=run_id,
            route_id=route.route_id,
            func_ea_hex=func_hex,
            func_ea_i64=func_i64,
            phase=route.reference_phase,
            owner_ea_hex=owner_hex,
            owner_ea_i64=owner_i64,
            rewrite_anchor_ea_hex=anchor_hex,
            rewrite_anchor_ea_i64=anchor_i64,
            corridor_json=corridor_json,
            original_transfer_kind=route.original_transfer_kind.value,
            final_transfer_kind=route.final_transfer_kind.value,
            direct_target_ea_hex=direct_hex,
            direct_target_ea_i64=direct_i64,
            true_target_ea_hex=true_hex,
            true_target_ea_i64=true_i64,
            false_target_ea_hex=false_hex,
            false_target_ea_i64=false_i64,
            predicate_kind=route.predicate_kind,
            reference_ledger_identity=route.reference_ledger_identity,
            reference_ledger_json=json.dumps(
                json.loads(route.reference_ledger_json),
                sort_keys=True,
                separators=(",", ":"),
            ),
        )


def record_route_oracle_capture(
    conn: sqlite3.Connection,
    capture: RouteOracleCapture,
) -> None:
    """Link one serialized MBA snapshot to a run, lane, and maturity."""

    del conn
    database = _write_db()
    with diag_models_on(database), database.atomic():
        SemanticRouteOracleCaptureRecord.create(
            run=capture.run_id,
            lane=capture.lane.value,
            candidate_variant=capture.candidate_variant,
            maturity=capture.maturity,
            snapshot=capture.snapshot_id,
            binary_sha256=capture.binary_sha256.lower(),
            d810_enabled=int(capture.d810_enabled),
            cache_disabled=int(capture.cache_disabled),
            metadata_json=json.dumps(
                json.loads(capture.metadata_json),
                sort_keys=True,
                separators=(",", ":"),
            ),
        )


def record_route_oracle_comparisons(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    reference_snapshot_ids: Mapping[str, int],
    candidate_snapshot_ids: Mapping[str, int],
    comparisons: Sequence[RouteOracleComparison],
) -> None:
    """Persist normalized route comparisons with both snapshot authorities."""

    del conn
    rows: list[dict[str, object]] = []
    for comparison in comparisons:
        if comparison.maturity not in reference_snapshot_ids:
            raise ValueError(f"missing reference snapshot for {comparison.maturity}")
        if comparison.maturity not in candidate_snapshot_ids:
            raise ValueError(f"missing candidate snapshot for {comparison.maturity}")
        owner_hex, owner_i64 = _dual(comparison.owner_ea)
        anchor_hex, anchor_i64 = _dual(comparison.rewrite_anchor_ea)
        rows.append(
            {
                "run": run_id,
                "route_id": comparison.route_id,
                "maturity": comparison.maturity,
                "candidate_variant": comparison.candidate_variant,
                "reference_snapshot": reference_snapshot_ids[comparison.maturity],
                "candidate_snapshot": candidate_snapshot_ids[comparison.maturity],
                "outcome": comparison.outcome,
                "first_divergence": int(comparison.first_divergence),
                "failed_invariant": comparison.failed_invariant,
                "owner_ea_hex": owner_hex,
                "owner_ea_i64": owner_i64,
                "rewrite_anchor_ea_hex": anchor_hex,
                "rewrite_anchor_ea_i64": anchor_i64,
                "oracle_shape_json": (
                    None
                    if comparison.oracle_shape is None
                    else comparison.oracle_shape.to_json()
                ),
                "candidate_shape_json": (
                    None
                    if comparison.candidate_shape is None
                    else comparison.candidate_shape.to_json()
                ),
                "reason": comparison.reason,
            }
        )
    if not rows:
        return
    database = _write_db()
    with diag_models_on(database), database.atomic():
        SemanticRouteOracleComparisonRecord.insert_many(rows).execute()


def load_snapshot_blocks(
    conn: sqlite3.Connection,
    snapshot_id: int,
) -> tuple[BlockSnapshot, ...]:
    """Reload one persisted MBA snapshot into neutral observation records."""

    instruction_rows = conn.execute(
        """
        SELECT block_serial, insn_index, ea_hex, ea_i64, opcode, opcode_name,
               iprops, is_assert, dest_type, dest_stkoff, dest_size,
               src_l_type, src_l_stkoff, src_l_value_hex, src_l_value_i64,
               src_r_type, src_r_stkoff, src_r_value_hex, src_r_value_i64,
               dstr, meta
        FROM instructions
        WHERE snapshot_id=?
        ORDER BY block_serial, insn_index
        """,
        (int(snapshot_id),),
    ).fetchall()
    instructions_by_block: dict[int, list[InstructionSnapshot]] = {}
    for row in instruction_rows:
        block_serial = int(row[0])
        instructions_by_block.setdefault(block_serial, []).append(
            InstructionSnapshot(
                index=int(row[1]),
                ea=int(_unsigned_from_dual(row[2], row[3]) or 0),
                opcode=int(row[4]),
                opcode_name=str(row[5]),
                iprops=int(row[6]),
                is_assert=bool(row[7]),
                dest_type=row[8],
                dest_stkoff=row[9],
                dest_size=row[10],
                src_l_type=row[11],
                src_l_stkoff=row[12],
                src_l_value=_unsigned_from_dual(row[13], row[14]),
                src_r_type=row[15],
                src_r_stkoff=row[16],
                src_r_value=_unsigned_from_dual(row[17], row[18]),
                dstr=str(row[19] or ""),
                meta=row[20],
            )
        )

    blocks: list[BlockSnapshot] = []
    for row in conn.execute(
        """
        SELECT serial, block_type, type_name, start_ea_hex, start_ea_i64,
               end_ea_hex, end_ea_i64, nsucc, npred, succs, preds, meta
        FROM blocks
        WHERE snapshot_id=?
        ORDER BY serial
        """,
        (int(snapshot_id),),
    ):
        serial = int(row[0])
        blocks.append(
            BlockSnapshot(
                serial=serial,
                block_type=int(row[1]),
                type_name=str(row[2]),
                start_ea=_unsigned_from_dual(row[3], row[4]),
                end_ea=_unsigned_from_dual(row[5], row[6]),
                nsucc=int(row[7]),
                npred=int(row[8]),
                succs=[int(value) for value in json.loads(row[9])],
                preds=[int(value) for value in json.loads(row[10])],
                instructions=instructions_by_block.get(serial, []),
                meta=row[11],
            )
        )
    return tuple(blocks)


__all__ = [
    "load_snapshot_blocks",
    "record_route_oracle_capture",
    "record_route_oracle_comparisons",
    "record_route_oracle_run",
    "record_route_reference_rewrite",
]
