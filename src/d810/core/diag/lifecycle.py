"""Writers for the event-native diagnostic lifecycle timeline."""

from __future__ import annotations

import json
import sqlite3
import time

from d810.core.observability_events import (
    DiagnosticSessionObserved,
    LifecycleEventObserved,
)


def _func_hex(func_ea: int) -> str:
    return f"0x{int(func_ea) & 0xFFFFFFFFFFFFFFFF:016x}"


def persist_diagnostic_session(
    conn: sqlite3.Connection,
    event: DiagnosticSessionObserved,
) -> None:
    timestamp = float(event.timestamp or time.time())
    existing = conn.execute(
        "SELECT started_at,diagnostic_error_count FROM diagnostic_sessions "
        "WHERE session_id=?",
        (str(event.session_id),),
    ).fetchone()
    started_at = timestamp if existing is None else float(existing[0])
    error_count = 0 if existing is None else int(existing[1])
    finished_at = None if event.status == "active" else timestamp
    conn.execute(
        "INSERT OR REPLACE INTO diagnostic_sessions "
        "(session_id,func_ea_hex,func_ea_i64,top_level_epoch,native_key_json,"
        "started_at,finished_at,status,diagnostic_error_count) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (
            str(event.session_id),
            _func_hex(event.func_ea),
            int(event.func_ea),
            int(event.top_level_epoch),
            str(event.native_key_json),
            started_at,
            finished_at,
            str(event.status),
            error_count,
        ),
    )


def persist_lifecycle_event(
    conn: sqlite3.Connection,
    event: LifecycleEventObserved,
    *,
    snapshot_id: int | None,
) -> int:
    row = conn.execute(
        "SELECT COALESCE(MAX(event_seq),0)+1 FROM lifecycle_events "
        "WHERE session_id=?",
        (str(event.session_id),),
    ).fetchone()
    event_seq = int(row[0])
    cursor = conn.execute(
        "INSERT INTO lifecycle_events "
        "(session_id,event_seq,timestamp,event_kind,snapshot_id,func_ea_hex,"
        "func_ea_i64,provider,maturity,phase,evidence_generation,"
        "mba_generation_before,mba_generation_after,correlation_id,summary,"
        "payload_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            str(event.session_id),
            event_seq,
            float(event.timestamp or time.time()),
            str(event.event_kind),
            snapshot_id,
            _func_hex(event.func_ea),
            int(event.func_ea),
            event.provider,
            event.maturity,
            event.phase,
            event.evidence_generation,
            event.mba_generation_before,
            event.mba_generation_after,
            event.correlation_id,
            str(event.summary),
            json.dumps(event.payload, sort_keys=True, separators=(",", ":")),
        ),
    )
    return int(cursor.lastrowid)


__all__ = ["persist_diagnostic_session", "persist_lifecycle_event"]
