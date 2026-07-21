"""Event-native lifecycle, evidence-lineage, and mutation-batch queries."""

from __future__ import annotations

import sqlite3

from d810.core.formatting import format_block_id
from d810.core.typing import Any


def _rows(cursor: sqlite3.Cursor) -> list[dict[str, Any]]:
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def lifecycle_timeline(
    conn: sqlite3.Connection,
    *,
    session_id: str | None = None,
    func_ea: int | None = None,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if session_id is not None:
        clauses.append("session_id=?")
        params.append(session_id)
    if func_ea is not None:
        clauses.append("func_ea_i64=?")
        params.append(int(func_ea))
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    return _rows(conn.execute(
        "SELECT * FROM lifecycle_timeline" + where
        + " ORDER BY timestamp,event_id",
        tuple(params),
    ))


def mutation_batch(conn: sqlite3.Connection, batch_id: str) -> dict[str, Any]:
    plan_rows = _rows(conn.execute(
        "SELECT le.event_id,le.session_id,le.event_seq,le.timestamp,"
        "le.func_ea_hex,le.maturity,le.evidence_generation,"
        "le.mba_generation_before AS mba_generation,le.summary,"
        "COUNT(p.item_index) AS persisted_item_count,"
        "CAST(json_extract(le.payload_json,'$.planned_operation_count') AS INTEGER) "
        "AS planned_operation_count "
        "FROM lifecycle_events le LEFT JOIN mutation_plan_items p "
        "ON p.event_id=le.event_id WHERE le.event_kind='mutation_plan' "
        "AND le.correlation_id=? GROUP BY le.event_id",
        (batch_id,),
    ))
    items = _rows(conn.execute(
        "SELECT p.* FROM mutation_plan_items p JOIN lifecycle_events le "
        "ON le.event_id=p.event_id WHERE p.mutation_batch_id=? "
        "ORDER BY p.item_index",
        (batch_id,),
    ))
    for item in items:
        item["source_block"] = _block_label(
            item["source_serial"], item["source_anchor_ea_hex"]
        )
        item["target_block"] = _block_label(
            item["target_serial"], item["target_anchor_ea_hex"]
        )
    receipt_rows = _rows(conn.execute(
        "SELECT r.*,le.session_id,le.event_seq,le.timestamp,le.func_ea_hex,"
        "le.maturity,le.evidence_generation FROM mutation_receipts r "
        "JOIN lifecycle_events le ON le.event_id=r.event_id "
        "WHERE r.mutation_batch_id=?",
        (batch_id,),
    ))
    identities = _rows(conn.execute(
        "SELECT ri.* FROM mutation_receipt_identities ri "
        "JOIN mutation_receipts r ON r.event_id=ri.event_id "
        "WHERE r.mutation_batch_id=? ORDER BY ri.identity_index",
        (batch_id,),
    ))
    return {
        "batch_id": batch_id,
        "plan": plan_rows[0] if plan_rows else None,
        "items": items,
        "receipt": receipt_rows[0] if receipt_rows else None,
        "receipt_identities": identities,
    }


def evidence_lineage(
    conn: sqlite3.Connection,
    *,
    session_id: str | None = None,
    func_ea: int | None = None,
) -> list[dict[str, Any]]:
    clauses = ["le.event_kind IN ('evidence_generation','identity_decision')"]
    params: list[Any] = []
    if session_id is not None:
        clauses.append("le.session_id=?")
        params.append(session_id)
    if func_ea is not None:
        clauses.append("le.func_ea_i64=?")
        params.append(int(func_ea))
    rows = _rows(conn.execute(
        "SELECT le.event_id,le.session_id,le.event_seq,le.timestamp,"
        "le.event_kind,le.func_ea_hex,le.maturity,le.phase,"
        "le.evidence_generation,le.mba_generation_before,le.summary,"
        "e.operation,e.previous_generation,e.resulting_generation,"
        "e.evidence_family,e.outcome AS evidence_outcome,e.owner,e.reason AS evidence_reason,"
        "i.decision_kind,i.consumer,i.identity_role,i.primary_anchor_ea_hex,"
        "i.current_serial,i.outcome AS identity_outcome,i.reason AS identity_reason "
        "FROM lifecycle_events le "
        "LEFT JOIN evidence_generation_events e ON e.event_id=le.event_id "
        "LEFT JOIN identity_decisions i ON i.event_id=le.event_id WHERE "
        + " AND ".join(clauses)
        + " ORDER BY le.timestamp,le.event_id",
        tuple(params),
    ))
    for row in rows:
        row["identity"] = _block_label(
            row["current_serial"], row["primary_anchor_ea_hex"]
        )
    return rows


def _block_label(serial: int | None, anchor_hex: str | None) -> str:
    if serial is None and anchor_hex is None:
        return "-"
    if serial is None:
        return f"ea@{anchor_hex}"
    return format_block_id(serial, start_ea=anchor_hex, synthetic=False)


def render_timeline(rows: list[dict[str, Any]]) -> str:
    lines = ["session\tseq\ttime\tkind\tmaturity\tevidence\tmba\toutcome\tidentity\tsummary"]
    for row in rows:
        mba = _generation_range(row["mba_generation_before"], row["mba_generation_after"])
        identity = _block_label(row["block_serial"], row["ea_anchor_hex"])
        lines.append("\t".join(str(value) for value in (
            row["session_id"], row["event_seq"], row["timestamp"], row["event_kind"],
            row["maturity"] or "-", _value(row["evidence_generation"]), mba,
            row["outcome"] or "-", identity, row["summary"],
        )))
    return "\n".join(lines)


def render_mutation_batch(result: dict[str, Any]) -> str:
    if result["plan"] is None and result["receipt"] is None:
        return f"mutation batch {result['batch_id']} not found"
    lines = [f"mutation batch {result['batch_id']}"]
    plan = result["plan"]
    if plan is not None:
        lines.append(
            f"plan session={plan['session_id']} seq={plan['event_seq']} "
            f"generation={plan['mba_generation']} count={plan['planned_operation_count']}"
        )
    for item in result["items"]:
        lines.append(
            f"item[{item['item_index']}] {item['mutation_kind']} "
            f"{item['source_block']} -> {item['target_block']} "
            f"{item['disposition']} reason={item['reason']}"
        )
    receipt = result["receipt"]
    if receipt is None:
        lines.append("receipt missing")
    else:
        lines.append(
            f"receipt seq={receipt['event_seq']} outcome={receipt['outcome']} "
            f"generation={receipt['pre_generation']}->{receipt['post_generation']} "
            f"applied={receipt['applied_operation_count']}/{receipt['planned_operation_count']}"
        )
    return "\n".join(lines)


def render_evidence_lineage(rows: list[dict[str, Any]]) -> str:
    lines = ["session\tseq\tkind\tmaturity\tevidence\tmba\tfamily/consumer\toutcome\tidentity\treason"]
    for row in rows:
        lines.append("\t".join(str(value) for value in (
            row["session_id"], row["event_seq"], row["event_kind"], row["maturity"] or "-",
            _value(row["evidence_generation"]), _value(row["mba_generation_before"]),
            row["evidence_family"] or row["consumer"] or "-",
            row["evidence_outcome"] or row["identity_outcome"] or "-",
            row["identity"], row["evidence_reason"] or row["identity_reason"] or "-",
        )))
    return "\n".join(lines)


def _generation_range(before: int | None, after: int | None) -> str:
    if before is None and after is None:
        return "-"
    if before == after:
        return _value(before)
    return f"{_value(before)}->{_value(after)}"


def _value(value: Any) -> str:
    return "-" if value is None else str(value)


__all__ = [
    "evidence_lineage", "lifecycle_timeline", "mutation_batch",
    "render_evidence_lineage", "render_mutation_batch", "render_timeline",
]
